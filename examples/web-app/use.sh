# Source from examples/web-app on the workstation to act as a role:
#
#   export WEISTACK=https://192.168.1.20:8781   # the cloud machine's -lan address
#   . ./use.sh deployer                       # or: operator
#
# It sets what each tool reads: the role's keys, the region, the proxy (the
# tools keep Huawei Cloud's real endpoints) and the system CA bundle, which
# holds WeiStack's CA after step 2.
: "${WEISTACK:?set WEISTACK to the cloud machine, for example https://192.168.1.20:8781}"
role="${1:?usage: . ./use.sh deployer|operator}"
if [ ! -r "secrets/$role.csv" ]; then
	echo "use.sh: no secrets/$role.csv; run step 3 first" >&2
	return 1
fi
IFS=, read -r _ ak sk < <(tail -n 1 "secrets/$role.csv" | tr -d '\r')

# Terraform, KooCLI and the SDK examples read these.
export HW_ACCESS_KEY="$ak" HW_SECRET_KEY="$sk" HW_REGION_NAME=ap-southeast-1
export HUAWEICLOUD_SDK_AK="$ak" HUAWEICLOUD_SDK_SK="$sk"
# The AWS CLI signs OBS requests with the same keys.
export AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_DEFAULT_REGION=ap-southeast-1

# Every *.myhuaweicloud.com request goes to WeiStack. Over -lan WeiStack
# answers only the hosts it emulates, so KooCLI's metadata downloads go
# direct.
export HTTPS_PROXY="$WEISTACK" https_proxy="$WEISTACK"
# Requests addressed to the cloud machine itself (the AWS CLI's endpoint) go
# straight to it too.
host="${WEISTACK#https://}"; host="${host%%:*}"
export NO_PROXY="$host,apiexplorer.ap-southeast-1.myhuaweicloud.com,apiexplorer.ap-southeast-3.myhuaweicloud.com,ap-southeast-1-hwcloudcli.obs.ap-southeast-1.myhuaweicloud.com,ap-southeast-3-hwcloudcli.obs.ap-southeast-3.myhuaweicloud.com,localhost,127.0.0.1"
export no_proxy="$NO_PROXY"

# Python and the AWS CLI bring their own CA list; point them at the system's.
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# `direct terraform init`, `direct go build`: downloads from the internet
# (providers, modules) skip WeiStack, which answers only Huawei Cloud's
# hosts over -lan. Both spellings of the proxy variable must go: tools
# fall back from one to the other.
direct() { env -u HTTPS_PROXY -u https_proxy "$@"; }

echo "acting as web-app-$role ($ak) through $WEISTACK"
unset ak sk role host
