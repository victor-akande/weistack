#!/usr/bin/env bash
# Runs the guide's steps 3 to 9 and 11 end to end, as README.md does them, and
# fails on the first step that does not do what the guide says. CI runs it
# (ci/web-app.yml); you can run it on the workstation too.
#
#   WEISTACK=https://10.1.1.64:8781 ADMIN_AK=... ADMIN_SK=... ./test.sh
#
# Needs terraform, python with requirements.txt, the AWS CLI, curl and jq,
# and bin/smoke (go build -o bin/smoke ./smoke). KooCLI (hcloud) is used
# when installed. ADMIN_AK and ADMIN_SK are the administrator's keys
# (`weistack credentials` on the cloud machine).
set -euo pipefail
cd "$(dirname "$0")"
: "${WEISTACK:?}" "${ADMIN_AK:?}" "${ADMIN_SK:?}"
export TF_IN_AUTOMATION=1 TF_INPUT=0
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
out() { terraform -chdir=infra output -raw "$1"; }
smoke() {
	./bin/smoke -project "$PROJECT" -pool "$(out pool_id)" -nat "$(out nat_gateway_id)" \
		-db "$(out db_id)" -servers "$(out web_server_count)"
}
as_admin() { (export HW_ACCESS_KEY="$ADMIN_AK" HW_SECRET_KEY="$ADMIN_SK" HTTPS_PROXY="$WEISTACK"; "$@"); }

step "3. The administrator creates the deployer and the operator"
install -d -m 700 secrets
[ -s secrets/operator-password ] || (umask 077; echo "Ops-1$(openssl rand -hex 8)" >secrets/operator-password)
HTTPS_PROXY= terraform -chdir=iam init >/dev/null
TF_VAR_operator_password="$(cat secrets/operator-password)" as_admin terraform -chdir=iam apply -auto-approve >/dev/null
PROJECT="$(terraform -chdir=iam output -raw project_id)"
[ -s secrets/deployer.csv ] && [ -s secrets/operator.csv ] || fail "the access keys were not saved"

step "4. The deployer applies the stack"
. ./use.sh deployer
[ -s secrets/db-password ] || (umask 077; echo "Db-1$(openssl rand -hex 8)" >secrets/db-password)
export TF_VAR_project_id="$PROJECT" TF_VAR_db_password="$(cat secrets/db-password)"
HTTPS_PROXY= terraform -chdir=infra init >/dev/null
terraform -chdir=infra apply -auto-approve >/dev/null
terraform -chdir=infra plan -detailed-exitcode >/dev/null || fail "a second plan found changes"
echo "applied; a second plan finds no changes"

step "5. The operator looks around with curl and KooCLI"
. ./use.sh operator
TOKEN="$(curl -sS -D - -o /dev/null "https://iam.$HW_REGION_NAME.myhuaweicloud.com/v3/auth/tokens" \
	-H 'Content-Type: application/json' -d @- <<JSON | tr -d '\r' | sed -n 's/^[Xx]-[Ss]ubject-[Tt]oken: //p'
{"auth": {"identity": {"methods": ["password"], "password": {"user": {
  "name": "web-app-operator", "password": "$(cat secrets/operator-password)", "domain": {"name": "weistack"}}}},
  "scope": {"project": {"id": "$PROJECT"}}}}
JSON
)"
[ -n "$TOKEN" ] || fail "no token"
online="$(curl -sS "https://elb.$HW_REGION_NAME.myhuaweicloud.com/v3/$PROJECT/elb/pools/$(out pool_id)/members" \
	-H "X-Auth-Token: $TOKEN" | jq '[.members[] | select(.operating_status == "ONLINE")] | length')"
[ "$online" = 2 ] || fail "$online members ONLINE, want 2"
status="$(curl -sS -o /dev/null -w '%{http_code}' "https://vpc.$HW_REGION_NAME.myhuaweicloud.com/v1/$PROJECT/vpcs" \
	-H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"vpc":{"name":"rogue","cidr":"172.16.0.0/16"}}')"
[ "$status" = 403 ] || fail "the operator's VPC creation answered $status, want 403"
echo "token works; 2 members ONLINE; the operator may not create a VPC"
if command -v hcloud >/dev/null; then
	hcloud configure set --cli-agree-privacy-statement=true >/dev/null
	hcloud configure set --cli-profile=web-app-operator --cli-mode=AKSK --cli-region="$HW_REGION_NAME" \
		--cli-access-key="$HW_ACCESS_KEY" --cli-secret-key="$HW_SECRET_KEY" --cli-project-id="$PROJECT" >/dev/null
	n="$(hcloud ECS ListServersDetails --cli-profile=web-app-operator | jq '[.servers[] | select(.status == "ACTIVE")] | length')"
	[ "$n" = 2 ] || fail "KooCLI lists $n ACTIVE servers, want 2"
	echo "KooCLI lists 2 ACTIVE servers"
else
	echo "KooCLI not installed: skipped"
fi

step "6. The deployer releases the site"
. ./use.sh deployer
python release.py v1

step "7. The deployer syncs backups with the AWS CLI"
mkdir -p backups && echo "-- web-app database dump" | gzip >"backups/db-$(date -u +%Y%m%d).sql.gz"
aws configure set default.s3.addressing_style path
aws --endpoint-url "$WEISTACK/obs" s3 sync backups/ "s3://$(out bucket)/backups/" \
	--sse aws:kms --sse-kms-key-id "$(out kms_key_id)" --only-show-errors
aws --endpoint-url "$WEISTACK/obs" s3 ls "s3://$(out bucket)/" --recursive | grep -q "backups/db-" || fail "no backup in the bucket"
echo "backups synced"

step "8. The operator runs the smoke check"
. ./use.sh operator
smoke

step "9. The deployer scales the web tier to 3"
. ./use.sh deployer
TF_VAR_web_servers=3 terraform -chdir=infra apply -auto-approve >/dev/null
. ./use.sh operator
smoke

step "11. Everything is torn down"
. ./use.sh deployer
aws --endpoint-url "$WEISTACK/obs" s3 rm "s3://$(out bucket)/" --recursive --only-show-errors
TF_VAR_web_servers=3 terraform -chdir=infra destroy -auto-approve >/dev/null
TF_VAR_operator_password="$(cat secrets/operator-password)" as_admin terraform -chdir=iam destroy -auto-approve >/dev/null
[ -z "$(terraform -chdir=infra state list)$(terraform -chdir=iam state list)" ] || fail "resources are left in a state"
rm -rf secrets site backups
echo "everything is destroyed"
echo
echo "PASS: the guide's steps 3 to 9 and 11 work"
