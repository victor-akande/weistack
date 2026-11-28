#!/usr/bin/env bash
# Runs the guide's steps 3 to 10 and 12 end to end, as README.md does them,
# and fails on the first step that does not do what the guide says. CI runs
# it (ci/keys-and-secrets.yml); you can run it on the workstation too.
#
#   WEISTACK=https://192.168.1.20:8781 ADMIN_AK=... ADMIN_SK=... ./test.sh
#
# Needs terraform, python with requirements.txt, the AWS CLI, curl, jq and
# openssl, and bin/check (cd check && go build -o ../bin/check .). KooCLI
# (hcloud) is used when installed. ADMIN_AK and ADMIN_SK are the
# administrator's keys (`weistack credentials` on the cloud machine).
set -euo pipefail
cd "$(dirname "$0")"
: "${WEISTACK:?}" "${ADMIN_AK:?}" "${ADMIN_SK:?}"
export TF_IN_AUTOMATION=1 TF_INPUT=0
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
out() { terraform -chdir=infra output -raw "$1"; }
as_admin() { (export HW_ACCESS_KEY="$ADMIN_AK" HW_SECRET_KEY="$ADMIN_SK" HTTPS_PROXY="$WEISTACK"; "$@"); }
fingerprint() { ssh-keygen -l -E md5 -f "$1" | awk '{print $2}' | sed 's/^MD5://'; }

step "3. The administrator creates the deployer, the operator and the app"
install -d -m 700 secrets
[ -s secrets/operator-password ] || (umask 077; echo "Ops-1$(openssl rand -hex 8)" >secrets/operator-password)
env -u HTTPS_PROXY -u https_proxy terraform -chdir=iam init >/dev/null
TF_VAR_operator_password="$(cat secrets/operator-password)" as_admin terraform -chdir=iam apply -auto-approve >/dev/null
PROJECT="$(terraform -chdir=iam output -raw project_id)"
for role in deployer operator app; do [ -s "secrets/$role.csv" ] || fail "no access key for $role"; done
echo "three users, each with its own access key"

step "4. The deployer applies the stack"
. ./use.sh deployer
export TF_VAR_project_id="$PROJECT"
direct terraform -chdir=infra init >/dev/null
terraform -chdir=infra apply -auto-approve >/dev/null
terraform -chdir=infra plan -detailed-exitcode >/dev/null || fail "a second plan found changes"
chmod 600 secrets/bastion.pem
[ "$(fingerprint secrets/bastion.pem)" = "$(out keypair_fingerprint)" ] || fail "the saved key is not the key pair's"
echo "applied; a second plan finds no changes; secrets/bastion.pem is the key pair's private key"

step "5. The deployer uploads the app's configuration with the AWS CLI"
jq -n --arg secret "$(out secret_name)" --arg region "$HW_REGION_NAME" \
	'{region: $region, api_token_secret: $secret}' >secrets/config.json
aws configure set default.s3.addressing_style path
aws --endpoint-url "$WEISTACK/obs" s3 cp secrets/config.json "s3://$(out bucket)/config.json" \
	--sse aws:kms --sse-kms-key-id "$(out kms_key_id)" --only-show-errors
sse="$(aws --endpoint-url "$WEISTACK/obs" s3api head-object --bucket "$(out bucket)" --key config.json | jq -r .ServerSideEncryption)"
[ "$sse" = "aws:kms" ] || fail "config.json is encrypted with $sse, want aws:kms"
grep -q "$(out secret_name)" secrets/config.json && echo "config.json names the secret, KMS-encrypted"

step "6. The app reads its token"
. ./use.sh app
read1="$(python app/api_token.py read)"
echo "$read1"
grep -q "version v1 (SYSCURRENT)" <<<"$read1" || fail "the app did not get v1"

step "7. The deployer rotates the token, and the app picks it up"
. ./use.sh deployer
python app/api_token.py rotate
. ./use.sh app
read2="$(python app/api_token.py read)"
echo "$read2"
grep -q "version v2 (SYSCURRENT)" <<<"$read2" || fail "the app did not get v2"
[ "${read1##* }" != "${read2##* }" ] || fail "the token did not change"
. ./use.sh deployer
terraform -chdir=infra plan -detailed-exitcode >/dev/null || fail "the rotation shows as drift"
echo "Terraform ignores the rotation"

step "8. The operator checks the stack with the Go SDK, KooCLI and curl"
. ./use.sh operator
./bin/check -project "$PROJECT" -server "$(out server_id)" -keypair "$(out keypair)" \
	-key-file secrets/bastion.pem -secret "$(out secret_name)"
if command -v hcloud >/dev/null; then
	hcloud configure set --cli-agree-privacy-statement=true >/dev/null
	hcloud configure set --cli-profile=keys-operator --cli-mode=AKSK --cli-region="$HW_REGION_NAME" \
		--cli-access-key="$HW_ACCESS_KEY" --cli-secret-key="$HW_SECRET_KEY" --cli-project-id="$PROJECT" >/dev/null
	hcloud KPS ListKeypairs --cli-profile=keys-operator | jq -e --arg k "$(out keypair)" \
		'[.keypairs[].keypair.name] | index($k)' >/dev/null || fail "KooCLI does not list the key pair"
	hcloud CSMS ListSecrets --cli-profile=keys-operator | jq -e --arg s "$(out secret_name)" \
		'[.secrets[].name] | index($s)' >/dev/null || fail "KooCLI does not list the secret"
	# KooCLI exits 0 on an API error too: the answer is in what it prints.
	answer="$(hcloud CSMS ShowSecretVersion --cli-profile=keys-operator --secret_name="$(out secret_name)" --version_id=latest 2>&1)"
	grep -q '"error_code": "CSMS.0302"' <<<"$answer" || fail "KooCLI was not refused the secret's value as the operator"
	echo "KooCLI lists the key pair and the secret, and cannot read the value"
else
	echo "KooCLI not installed: skipped"
fi
TOKEN="$(curl -sS -D - -o /dev/null "https://iam.$HW_REGION_NAME.myhuaweicloud.com/v3/auth/tokens" \
	-H 'Content-Type: application/json' -d @- <<JSON | tr -d '\r' | sed -n 's/^[Xx]-[Ss]ubject-[Tt]oken: //p'
{"auth": {"identity": {"methods": ["password"], "password": {"user": {
  "name": "keys-operator", "password": "$(cat secrets/operator-password)", "domain": {"name": "weistack"}}}},
  "scope": {"project": {"id": "$PROJECT"}}}}
JSON
)"
[ -n "$TOKEN" ] || fail "no token"
# A W3C trace ID: WeiStack joins the caller's trace and says so in
# traceresponse, and its log records the same trace_id (step 11).
trace="$(openssl rand -hex 16)"
headers="$(curl -sS -D - -o secrets/secrets.json "https://kms.$HW_REGION_NAME.myhuaweicloud.com/v1/$PROJECT/secrets" \
	-H "X-Auth-Token: $TOKEN" -H "traceparent: 00-$trace-$(openssl rand -hex 8)-01" | tr -d '\r')"
jq -e --arg s "$(out secret_name)" '[.secrets[].name] | index($s)' secrets/secrets.json >/dev/null || fail "curl does not list the secret"
grep -qi "^traceresponse: 00-$trace-" <<<"$headers" || fail "no traceresponse for trace $trace"
hint="$(curl -sS -D - -o /dev/null "https://kms.$HW_REGION_NAME.myhuaweicloud.com/v1/$PROJECT/secrets" \
	-H "X-Auth-Token: not-a-token" | tr -d '\r' | sed -n 's/^[Xx]-[Ww]ei[Ss]tack-[Hh]int: //p')"
[ -n "$hint" ] || fail "no X-WeiStack-Hint on a bad token"
echo "token works; trace $trace joined; a bad token's hint: $hint"

step "9. The administrator reads the inventory"
as_admin ./bin/check -inventory -server "$(out server_id)" -ids "$(
	printf '%s,' "ecs.cloudservers=$(out server_id)" "vpc.vpcs=$(out vpc_id)" "vpc.publicips=$(out eip_id)" \
		"evs.volumes=$(out volume_id)" "vpc.securityGroups=$(out security_group_id)" \
		"kps.keypairs=$(out keypair)" "csms.secrets=$(out secret_id)" "kms.keys=$(out kms_key_id)" "obs.buckets=$(out bucket)"
)"

step "10. The deployer recovers the private key from KPS"
if command -v hcloud >/dev/null; then
	. ./use.sh deployer
	hcloud configure set --cli-profile=keys-deployer --cli-mode=AKSK --cli-region="$HW_REGION_NAME" \
		--cli-access-key="$HW_ACCESS_KEY" --cli-secret-key="$HW_SECRET_KEY" --cli-project-id="$PROJECT" >/dev/null
	(umask 077; hcloud KPS ExportPrivateKey --cli-profile=keys-deployer --keypair.name="$(out keypair)" |
		jq -r .keypair.private_key >secrets/recovered.pem)
	[ "$(fingerprint secrets/recovered.pem)" = "$(out keypair_fingerprint)" ] || fail "the recovered key is not the key pair's"
	echo "KPS returned the same private key"
else
	echo "KooCLI not installed: skipped"
fi

step "12. Everything is torn down"
. ./use.sh deployer
aws --endpoint-url "$WEISTACK/obs" s3 rm "s3://$(out bucket)/" --recursive --only-show-errors
terraform -chdir=infra destroy -auto-approve >/dev/null
TF_VAR_operator_password="$(cat secrets/operator-password)" as_admin terraform -chdir=iam destroy -auto-approve >/dev/null
[ -z "$(terraform -chdir=infra state list)$(terraform -chdir=iam state list)" ] || fail "resources are left in a state"
rm -rf secrets
echo "everything is destroyed"
echo
echo "PASS: the guide's steps 3 to 10 and 12 work"
