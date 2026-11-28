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
#
# To rehearse before a release, give a locally built binary and an output
# directory outside the repository (a rehearsal is never committed):
#
#   WEISTACK_FIXTURE_BINARY=bin/weistack WEISTACK_FIXTURE_OUT=/tmp/fx generate.sh 0.3.0
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="${1:?usage: generate.sh <version, for example 0.1.1>}"
version="${version#v}"
out="$here/v$version/data"
binary="${WEISTACK_FIXTURE_BINARY:-}"
if [[ -n "$binary" ]]; then
	binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
	out="${WEISTACK_FIXTURE_OUT:?a rehearsal needs WEISTACK_FIXTURE_OUT, a directory outside the repository}/data"
	case "$(cd "$(dirname "$out")" 2>/dev/null && pwd || dirname "$out")/" in
	"$(git -C "$here" rev-parse --show-toplevel)"/*) echo "a rehearsal must not write into the repository" >&2; exit 1 ;;
	esac
fi
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
if [[ -n "$binary" ]]; then
	cp "$binary" weistack
else
	curl -fsSLO "$release/$archive"
	curl -fsSLO "$release/checksums.txt"
	sha256sum -c --ignore-missing checksums.txt
	tar -xzf "$archive" weistack
fi
./weistack version

# at_least VERSION: the release being written is VERSION or newer.
at_least() { [[ "$(printf '%s\n%s\n' "$1" "$version" | sort -V | head -n 1)" == "$1" ]]; }

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

extra=""
if at_least 0.3.0; then
	# Services and stored secrets added in v0.2 and v0.3: identity, KMS,
	# EIP, NAT, ELB and EVS data disks.
	domain=$(call GET /_weistack/services | field "['account_id']")
	user=$(call POST /iam/v3.0/OS-USER/users "{\"user\": {\"name\": \"fixture-user\", \"domain_id\": \"$domain\"}}" | field "['user']['id']")
	credential=$(call POST /iam/v3.0/OS-CREDENTIAL/credentials "{\"credential\": {\"user_id\": \"$user\", \"description\": \"fixture\"}}")
	access_key=$(field "['credential']['access']" <<<"$credential")
	secret_key=$(field "['credential']['secret']" <<<"$credential")

	kms_key=$(call POST "/kms/v1.0/$project/kms/create-key" '{"key_alias": "fixture-key"}' | field "['key_info']['key_id']")
	plain_text="sealed by WeiStack v${version}"
	cipher_text=$(call POST "/kms/v1.0/$project/kms/encrypt-data" "{\"key_id\": \"$kms_key\", \"plain_text\": \"$plain_text\"}" | field "['cipher_text']")

	public_ip=$(call POST "/vpc/v1/$project/publicips" \
		'{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "fixture-bandwidth", "size": 5, "share_type": "PER", "charge_mode": "traffic"}}' |
		field "['publicip']['id']")
	wait_for "/vpc/v1/$project/publicips/$public_ip" "['publicip']['status']" DOWN

	nat=$(call POST "/nat/v2/$project/nat_gateways" \
		"{\"nat_gateway\": {\"name\": \"fixture-nat\", \"router_id\": \"$vpc\", \"internal_network_id\": \"$subnet\", \"spec\": \"1\"}}" |
		field "['nat_gateway']['id']")
	wait_for "/nat/v2/$project/nat_gateways/$nat" "['nat_gateway']['status']" ACTIVE
	snat=$(call POST "/nat/v2/$project/snat_rules" \
		"{\"snat_rule\": {\"nat_gateway_id\": \"$nat\", \"network_id\": \"$subnet\", \"floating_ip_id\": \"$public_ip\"}}" |
		field "['snat_rule']['id']")
	wait_for "/nat/v2/$project/snat_rules/$snat" "['snat_rule']['status']" ACTIVE

	ipv4_subnet=$(call GET "/vpc/v1/$project/subnets/$subnet" | field "['subnet']['neutron_subnet_id']")
	l4=$(call GET "/elb/v3/$project/elb/flavors?type=L4" | field "['flavors'][0]['id']")
	l7=$(call GET "/elb/v3/$project/elb/flavors?type=L7" | field "['flavors'][0]['id']")
	lb=$(call POST "/elb/v3/$project/elb/loadbalancers" "{\"loadbalancer\": {\"name\": \"fixture-lb\", \"vpc_id\": \"$vpc\",
		\"vip_subnet_cidr_id\": \"$ipv4_subnet\", \"availability_zone_list\": [\"ap-southeast-1a\"],
		\"l4_flavor_id\": \"$l4\", \"l7_flavor_id\": \"$l7\"}}" | field "['loadbalancer']['id']")
	wait_for "/elb/v3/$project/elb/loadbalancers/$lb" "['loadbalancer']['provisioning_status']" ACTIVE
	pool=$(call POST "/elb/v3/$project/elb/pools" \
		"{\"pool\": {\"name\": \"fixture-pool\", \"protocol\": \"HTTP\", \"lb_algorithm\": \"ROUND_ROBIN\", \"loadbalancer_id\": \"$lb\"}}" |
		field "['pool']['id']")
	listener=$(call POST "/elb/v3/$project/elb/listeners" "{\"listener\": {\"name\": \"fixture-listener\", \"protocol\": \"HTTP\",
		\"protocol_port\": 80, \"loadbalancer_id\": \"$lb\", \"default_pool_id\": \"$pool\"}}" | field "['listener']['id']")
	server_ip=$(call GET "/ecs/v1/$project/cloudservers/$server" | field "['server']['addresses']['$vpc'][0]['addr']")
	member=$(call POST "/elb/v3/$project/elb/pools/$pool/members" \
		"{\"member\": {\"address\": \"$server_ip\", \"protocol_port\": 8080, \"subnet_cidr_id\": \"$ipv4_subnet\"}}" |
		field "['member']['id']")

	volume=$(call POST "/evs/v2.1/$project/cloudvolumes" \
		'{"volume": {"name": "fixture-data", "size": 10, "volume_type": "SSD", "availability_zone": "ap-southeast-1a"}}' |
		field "['volume_ids'][0]")
	wait_for "/evs/v2/$project/cloudvolumes/$volume" "['volume']['status']" available
	call POST "/ecs/v1/$project/cloudservers/$server/attachvolume" "{\"volumeAttachment\": {\"volumeId\": \"$volume\"}}" >/dev/null
	wait_for "/evs/v2/$project/cloudvolumes/$volume" "['volume']['status']" in-use
	snapshot=$(call POST "/evs/v2/$project/cloudsnapshots" "{\"snapshot\": {\"name\": \"fixture-snapshot\", \"volume_id\": \"$volume\", \"force\": true}}" |
		field "['snapshot']['id']")
	wait_for "/evs/v2/$project/cloudsnapshots/$snapshot" "['snapshot']['status']" available

	extra=",
 \"user\": \"$user\", \"access_key\": \"$access_key\", \"secret_key\": \"$secret_key\",
 \"kms_key\": \"$kms_key\", \"cipher_text\": \"$cipher_text\", \"plain_text\": \"$plain_text\",
 \"public_ip\": \"$public_ip\", \"nat_gateway\": \"$nat\", \"snat_rule\": \"$snat\",
 \"load_balancer\": \"$lb\", \"listener\": \"$listener\", \"pool\": \"$pool\", \"member\": \"$member\",
 \"volume\": \"$volume\", \"snapshot\": \"$snapshot\""
fi

if at_least 0.4.0; then
	# Added in v0.4: KPS key pairs whose private keys are kept sealed, one
	# by the vault key and one by the KMS key above, and a CSMS secret,
	# whose value a data key from KMS encrypts. ids.json records the key
	# pairs' fingerprints, never their private keys.
	keypair_body() { # keypair_body NAME ENCRYPTION
		echo "{\"keypair\": {\"name\": \"$1\", \"key_protection\": {\"encryption\": $2}}}"
	}
	keypair_fingerprint=$(call POST "/kms/v3/$project/keypairs" \
		"$(keypair_body fixture-keypair '{"type": "default"}')" | field "['keypair']['fingerprint']")
	kms_keypair_fingerprint=$(call POST "/kms/v3/$project/keypairs" \
		"$(keypair_body fixture-keypair-kms "{\"type\": \"kms\", \"kms_key_id\": \"$kms_key\"}")" | field "['keypair']['fingerprint']")

	secret_value="kept by WeiStack v${version}"
	secret=$(call POST "/kms/v1/$project/secrets" "{\"name\": \"fixture-secret\", \"secret_string\": \"$secret_value\"}" |
		field "['secret']['id']")

	extra="$extra,
 \"keypair\": \"fixture-keypair\", \"keypair_fingerprint\": \"$keypair_fingerprint\",
 \"kms_keypair\": \"fixture-keypair-kms\", \"kms_keypair_fingerprint\": \"$kms_keypair_fingerprint\",
 \"secret\": \"$secret\", \"secret_name\": \"fixture-secret\", \"secret_value\": \"$secret_value\""
fi

kill -INT "$pid"
wait "$pid" || true
pid=""
grep -E 'level=(WARN|ERROR)' "$work/log" && { echo "the emulator logged warnings or errors" >&2; exit 1; }
cat >"$out/ids.json" <<JSON
{"project": "$project", "vpc": "$vpc", "subnet": "$subnet", "security_group": "$group", "server": "$server",
 "image_job": "$job", "bucket": "fixture-bucket", "object": "notes/hello.txt", "bucket_owner": "AKFIXTURE", "rds": "$rds"$extra}
JSON
ls -l "$out"
echo "fixture written by $(cd "$work" && ./weistack version)"
