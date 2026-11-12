#!/usr/bin/env bash
# Writes the data directory of a released WeiStack into ./v<version>,
# using that release's own binary, so the upgrade test opens exactly what
# the release wrote:
#
#   generate.sh 0.1.1
#
# Every release gets a fixture, so an upgrade from any of them stays
# tested. The emulator runs as a user would start it, with -persist and no
# -project-id, so the project ID file is written too. Needs curl, python3,
# tar and sha256sum, and network access to the GitHub release.
#
# The CA goes to a scratch directory: v0.1.0 kept it in the data
# directory under -persist, and its private key must not be committed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="${1:?usage: generate.sh <version, for example 0.1.1>}"
version="${version#v}"
out="$here/v$version/data"
release="https://github.com/victor-akande/weistack/releases/download/v${version}"
work="$(mktemp -d)"
pid=""
cleanup() {
	if [[ -n "$pid" ]]; then kill -INT "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
	rm -rf "$work"
}
trap cleanup EXIT

case "$(uname -m)" in
x86_64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "unsupported machine $(uname -m)" >&2; exit 1 ;;
esac
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
archive="weistack_${version}_${os}_${arch}.tar.gz"

cd "$work"
curl -fsSLO "$release/$archive"
curl -fsSLO "$release/checksums.txt"
sha256sum -c --ignore-missing checksums.txt
tar -xzf "$archive" weistack
./weistack version

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
base="http://127.0.0.1:$port"
rm -rf "$out"
mkdir -p "$(dirname "$out")"
./weistack -persist -data-dir "$out" -tls-dir "$work/tls" -port "$port" \
	-lifecycle-delay 0 -log-format text >"$work/log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do curl -fsS "$base/_weistack/health" >/dev/null 2>&1 && break; sleep 0.1; done
project="$(curl -fsS "$base/_weistack/services" | python3 -c 'import json,sys; print(json.load(sys.stdin)["project_id"])')"

# call METHOD PATH [BODY] [extra curl args...] prints the response body and
# fails on an HTTP error.
call() {
	local method=$1 path=$2 body=${3:-}
	shift 3 || shift $#
	curl -fsS -X "$method" "$base$path" ${body:+-d "$body"} "$@"
}
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d' + sys.argv[1]))" "$1"; }
wait_for() { # wait_for PATH EXPR WANT
	for _ in $(seq 1 100); do
		[[ "$(call GET "$1" | field "$2")" == "$3" ]] && return 0
		sleep 0.1
	done
	echo "timed out waiting for $1 $2 == $3" >&2
	exit 1
}

vpc=$(call POST "/vpc/v1/$project/vpcs" '{"vpc": {"name": "fixture-vpc", "cidr": "192.168.0.0/16"}}' | field "['vpc']['id']")
wait_for "/vpc/v1/$project/vpcs/$vpc" "['vpc']['status']" OK
subnet=$(call POST "/vpc/v1/$project/subnets" \
	"{\"subnet\": {\"name\": \"fixture-subnet\", \"cidr\": \"192.168.1.0/24\", \"gateway_ip\": \"192.168.1.1\", \"vpc_id\": \"$vpc\"}}" |
	field "['subnet']['id']")
wait_for "/vpc/v1/$project/subnets/$subnet" "['subnet']['status']" ACTIVE
group=$(call POST "/vpc/v3/$project/vpc/security-groups" '{"security_group": {"name": "fixture-sg"}}' | field "['security_group']['id']")
call POST "/vpc/v3/$project/vpc/security-group-rules" \
	"{\"security_group_rule\": {\"security_group_id\": \"$group\", \"direction\": \"ingress\", \"ethertype\": \"IPv4\", \"protocol\": \"tcp\", \"multiport\": \"22\", \"remote_ip_prefix\": \"0.0.0.0/0\"}}" >/dev/null

server=$(call POST "/ecs/v1.1/$project/cloudservers" "{\"server\": {\"name\": \"fixture-server\",
	\"imageRef\": \"455b5860-f96d-5d89-baaa-ec6adb758c5b\", \"flavorRef\": \"s6.large.2\", \"vpcid\": \"$vpc\",
	\"nics\": [{\"subnet_id\": \"$subnet\"}], \"root_volume\": {\"volumetype\": \"GPSSD\"},
	\"security_groups\": [{\"id\": \"$group\"}]}}" | field "['serverIds'][0]")
wait_for "/ecs/v1/$project/cloudservers/$server" "['server']['status']" ACTIVE

job=$(call POST "/ims/v2/cloudimages/action" "{\"name\": \"fixture-image\", \"instance_id\": \"$server\"}" | field "['job_id']")
wait_for "/ims/v1/$project/jobs/$job" "['status']" SUCCESS

owner=(-H "Authorization: OBS AKFIXTURE:c2ln")
call PUT /obs/fixture-bucket "" "${owner[@]}" >/dev/null
call PUT /obs/fixture-bucket/notes/hello.txt "written by WeiStack v${version}" "${owner[@]}" -H "Content-Type: text/plain" >/dev/null

# RDS needs a password of four character kinds; WeiStack does not store it.
db_password="Ws-1$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
rds=$(call POST "/rds/v3/$project/instances" "{\"name\": \"fixture-mysql\", \"datastore\": {\"type\": \"MySQL\", \"version\": \"8.0\"},
	\"flavor_ref\": \"rds.mysql.n1.large.2\", \"volume\": {\"type\": \"CLOUDSSD\", \"size\": 40}, \"region\": \"ap-southeast-1\",
	\"availability_zone\": \"ap-southeast-1a\", \"vpc_id\": \"$vpc\", \"subnet_id\": \"$subnet\", \"security_group_id\": \"$group\",
	\"password\": \"$db_password\"}" | field "['instance']['id']")
wait_for "/rds/v3/$project/instances?id=$rds" "['instances'][0]['status']" ACTIVE

kill -INT "$pid"
wait "$pid" || true
pid=""
grep -E 'level=(WARN|ERROR)' "$work/log" && { echo "the emulator logged warnings or errors" >&2; exit 1; }
cat >"$out/ids.json" <<JSON
{"project": "$project", "vpc": "$vpc", "subnet": "$subnet", "security_group": "$group", "server": "$server",
 "image_job": "$job", "bucket": "fixture-bucket", "object": "notes/hello.txt", "bucket_owner": "AKFIXTURE", "rds": "$rds"}
JSON
ls -l "$out"
echo "fixture written by $(cd "$work" && ./weistack version)"
