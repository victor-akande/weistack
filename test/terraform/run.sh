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

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
project="0123456789abcdef0123456789abcdef"
admin="http://127.0.0.1:$port/_weistack"

step "Starting WeiStack on port $port"
"$bin" -port "$port" -project-id "$project" -lifecycle-delay 200ms \
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
cp "$here/main.tf" "$here/.terraform.lock.hcl" "$work/"
cd "$work"
export TF_IN_AUTOMATION=1 TF_INPUT=0 TF_VAR_project_id="$project"
# A fresh password per run, meeting RDS's rule of four character kinds.
TF_VAR_db_password="Ws-1$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
export TF_VAR_db_password

step "terraform init"
# Without the proxy: the provider comes from the public registry.
terraform init -no-color >/dev/null

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
        "bucket_domain": "tf-assets-bucket.obs.ap-southeast-1.myhuaweicloud.com"}
bad = {k: out.get(k) for k, v in want.items() if out.get(k) != v}
if not out.get("server_ip", "").startswith("192.168.1."):
    bad["server_ip"] = out.get("server_ip")
if bad:
    sys.exit(f"unexpected outputs: {bad}")
PY

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
# Job history, the seeded public images and the project default security
# group with its rules outlive the scenario, as in the real cloud.
kept = ("job", "ims.image", "vpc.secgroup", "vpc.secgroup-rule")
left = {scope: len(recs) for scope, recs in state.items()
        if recs and not scope.endswith(kept)}
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
