#!/usr/bin/env bash
# Runs the Terraform scenario in main.tf against a fresh WeiStack:
#
#   apply  -> every resource is created and reaches its final state
#   plan   -> no changes: every read matches what was written
#   destroy-> everything is deleted and the emulator is empty again
#
# Terraform reaches WeiStack only through HTTPS_PROXY, with passthrough
# off, so a request for anything WeiStack does not emulate fails instead
# of reaching the real cloud.
#
# With WEISTACK_TF_IAM=enforce the emulator runs with -iam=enforce and
# Terraform signs with the administrator's keys, which it gets as a user
# would, from `weistack credentials`.
#
# Needs terraform, go (unless WEISTACK_BIN names a built binary), curl
# and python3. Run from anywhere: make test-terraform.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/weistack-tf-XXXXXX")"
pid=""

cleanup() {
	status=$?
	if [[ -n "$pid" ]]; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	if [[ $status -ne 0 && -f "$work/weistack.log" ]]; then
		echo "--- emulator log (warnings and errors) ---" >&2
		grep -E 'level=(WARN|ERROR)' "$work/weistack.log" | tail -n 50 >&2 || true
	fi
	rm -rf "$work"
	exit $status
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }

bin="${WEISTACK_BIN:-}"
if [[ -z "$bin" ]]; then
	step "Building WeiStack"
	bin="$work/weistack"
	(cd "$root" && CGO_ENABLED=0 go build -o "$bin" ./cmd/weistack)
fi

iam="${WEISTACK_TF_IAM:-accept}"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
project="0123456789abcdef0123456789abcdef"
admin="http://127.0.0.1:$port/_weistack"

step "Starting WeiStack on port $port (-iam=$iam)"
"$bin" -port "$port" -project-id "$project" -lifecycle-delay 200ms -iam "$iam" \
	-proxy-passthrough none -tls-dir "$work/tls" -log-format text \
	>"$work/weistack.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
	curl -fsS "$admin/health" >/dev/null 2>&1 && break
	sleep 0.1
done
curl -fsS "$admin/health" >/dev/null

# The module is copied so that .terraform and the state stay out of the
# repository. The lock file pins the provider's checksums.
cp "$here"/*.tf "$here/.terraform.lock.hcl" "$work/"
mkdir "$work/assume"
cp "$here"/assume/*.tf "$here/.terraform.lock.hcl" "$work/assume/"
cd "$work"
export TF_IN_AUTOMATION=1 TF_INPUT=0 TF_VAR_project_id="$project"
TF_VAR_account_id="$(curl -fsS "$admin/services" | python3 -c 'import json, sys; print(json.load(sys.stdin)["account_id"])')"
export TF_VAR_account_id
# A second account, which the scenario's agencies delegate to.
partner="$(curl -fsS -X POST -H 'Content-Type: application/json' -d '{"name":"tf-partner"}' "$admin/accounts")"
partner_field() { python3 -c 'import json, sys; d = json.load(sys.stdin); print(d[sys.argv[1]][sys.argv[2]])' "$1" "$2" <<<"$partner"; }
TF_VAR_partner_id="$(partner_field account id)" TF_VAR_partner_name="$(partner_field account name)"
export TF_VAR_partner_id TF_VAR_partner_name
partner_ak="$(partner_field credentials access_key)" partner_sk="$(partner_field credentials secret_key)"
# Fresh passwords per run, for the RDS root user and the IAM user. Each
# has the four character kinds RDS requires: an upper-case letter, a
# symbol, a digit, and lower-case hex.
fresh_secret() { python3 -c 'import secrets; print("Ws-1" + secrets.token_hex(8))'; }
TF_VAR_db_password="$(fresh_secret)"
TF_VAR_iam_password="$(fresh_secret)"
export TF_VAR_db_password TF_VAR_iam_password
if [[ $iam == enforce ]]; then
	# Exports HW_ACCESS_KEY and HW_SECRET_KEY, among others.
	eval "$("$bin" credentials -tls-dir "$work/tls" 2>/dev/null)"
	export TF_VAR_access_key="$HW_ACCESS_KEY" TF_VAR_secret_key="$HW_SECRET_KEY"
fi

step "terraform init"
# Without the proxy: the provider comes from the public registry.
terraform init -no-color >/dev/null
terraform -chdir=assume init -no-color >/dev/null

# From here on every request goes through WeiStack.
export HTTPS_PROXY="http://127.0.0.1:$port" HTTP_PROXY="http://127.0.0.1:$port"

step "terraform apply"
terraform apply -auto-approve -no-color

step "Checking the outputs"
outputs="$(terraform output -json)"
echo "$outputs"
python3 - "$outputs" <<'PY'
import json, sys
out = {k: v["value"] for k, v in json.loads(sys.argv[1]).items()}
want = {"server_status": "ACTIVE", "rds_status": "ACTIVE",
        "bucket_domain": "tf-assets-bucket.obs.ap-southeast-1.myhuaweicloud.com",
        "kms": {"key_state": "2", "rotation": True, "data_key_chars": 128},
        "iam": {"v5_policy_type": "custom", "access_key_status": "active",
                "v5_policy_version": "v1", "v5_key_status": "active"}}
bad = {k: out.get(k) for k, v in want.items() if out.get(k) != v}
if not out.get("server_ip", "").startswith("192.168.1."):
    bad["server_ip"] = out.get("server_ip")
if bad:
    sys.exit(f"unexpected outputs: {bad}")
PY

step "Assuming the agencies from the partner account"
# Classic IAM's securitytokens and STS's AssumeAgency, with the
# provider's assume_role; the credentials' security token then goes with
# every request.
TF_VAR_partner_access_key="$partner_ak" TF_VAR_partner_secret_key="$partner_sk" \
	terraform -chdir=assume apply -auto-approve -no-color >"$work/assume.txt" 2>&1 || {
	cat "$work/assume.txt"
	exit 1
}
terraform -chdir=assume output -json vpcs | python3 -c '
import json, sys
vpcs = json.load(sys.stdin)
if vpcs != {"classic": 1, "sts": 1}:
    sys.exit(f"the assumed agencies see these VPCs: {vpcs}")
print("Both agencies read the VPC.")'

step "terraform plan (must show no changes)"
set +e
terraform plan -detailed-exitcode -no-color >"$work/plan.txt" 2>&1
plan=$?
set -e
if [[ $plan -ne 0 ]]; then
	cat "$work/plan.txt"
	echo "plan exited $plan: the second plan must find no changes" >&2
	exit 1
fi
echo "No changes."

step "terraform destroy"
terraform destroy -auto-approve -no-color

step "Checking that nothing is left"
unset HTTPS_PROXY HTTP_PROXY
curl -fsS "$admin/state" | python3 -c '
import json, sys
state = json.load(sys.stdin)["resources"]
def records(kind):
    return [r["data"] for scope, recs in state.items() if scope.endswith("/" + kind) for r in recs]
# Job history, the seeded public images, KMS keys (pending deletion, as
# in the cloud), the partner account, the
# projects, root users and built-in admin groups of both accounts, and
# the project default security group with its rules outlive the
# scenario, as in the real cloud. Every other IAM record (groups, keys,
# roles, grants, policies, attachments) must be gone.
kept = ("job", "ims.image", "kms.key", "iam.account", "iam.project", "iam.user", "iam.group", "vpc.secgroup", "vpc.secgroup-rule")
left = {scope: len(recs) for scope, recs in state.items()
        if recs and not scope.endswith(kept)}
users = [u["name"] for u in records("iam.user") if not u.get("root")]
if users:
    left["IAM users"] = users
user_groups = [g["name"] for g in records("iam.group") if g["name"] != "admin"]
if user_groups:
    left["IAM user groups"] = user_groups
groups = {g["id"]: g["name"] for g in records("vpc.secgroup")}
if any(name != "default" for name in groups.values()):
    left["security groups"] = sorted(groups.values())
orphans = [r["id"] for r in records("vpc.secgroup-rule") if r.get("security_group_id") not in groups]
if orphans:
    left["rules of deleted groups"] = orphans
if left:
    sys.exit(f"resources left after destroy: {left}")
'
echo "Nothing left."

step "Terraform scenario passed"
