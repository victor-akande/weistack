# Connecting clients

WeiStack speaks the real APIs, so Huawei's own tools work against it
unchanged. There are two ways to point a client at it.

- **As an HTTPS proxy (recommended).** The client keeps Huawei Cloud's real
  endpoints and sends its traffic through WeiStack, which answers for every
  host under `myhuaweicloud.com`. Nothing is configured per service, and
  nothing reaches the real cloud by mistake.
- **By endpoint.** The client sends its requests to WeiStack directly, with
  plain HTTP and a path prefix such as `http://127.0.0.1:8780/vpc`. This is
  for clients that let you override endpoints but not set a proxy.

Every client needs a few values. **Credentials** can be anything: WeiStack
reads the access key, to tell owners apart, but checks no signatures. The
**region** is `ap-southeast-1` unless you started WeiStack with `-region`.
The **project ID** comes from WeiStack itself:

```bash
curl -s http://localhost:8780/_weistack/services
```

## Trusting WeiStack's certificate

Through the proxy, HTTPS to `*.myhuaweicloud.com` is answered with
certificates from WeiStack's own certificate authority. Either trust that
CA, or tell the client to skip certificate verification. Every client below
can do one or the other. To fetch the CA:

```bash
curl -s -o ~/weistack-ca.pem http://localhost:8780/_weistack/ca
```

The CA is created once and kept in `~/.config/weistack/tls` (`/data/tls` in
the image), so you only fetch it once.

## How each guide was checked

| Client | Setup | Checked |
| --- | --- | --- |
| [Terraform](#terraform) | Proxy | Applied, re-planned and destroyed in CI (`test/terraform`) |
| [Go SDK](#go-sdk) | Proxy | In CI (`test/sdk`, `TestHTTPSProxy`) |
| [OBS SDK for Go](#obs-sdk-for-go) | Proxy, trusting the CA | In CI (`TestOBSThroughProxyTrustingTheCA`) |
| [AWS CLI and S3 SDKs](#aws-cli-and-s3-sdks) | Endpoint | Request shape in CI with the AWS SDK for Go (`TestS3OverPathPrefix`); the CLI itself not yet |
| [Python SDK](#python-sdk) | Proxy | From the SDK's documentation; not yet run against WeiStack |
| [OBS SDK for Python](#obs-sdk-for-python) | Proxy | From the SDK's source; not yet run against WeiStack |
| [KooCLI](#koocli) | Proxy | From KooCLI's documentation; not yet run against WeiStack |

If a guide marked "not yet" does not work for you, please open an issue.

## Terraform

See [getting started](getting-started.md#4-use-huaweis-terraform-provider)
for a complete example. In short, set `project_id` and any `domain_id` in
the provider block, add `skip_check_website_type = true` and
`skip_check_upgrade = true`, and then:

```bash
export HTTPS_PROXY=http://127.0.0.1:8780 SSL_CERT_FILE=~/weistack-ca.pem
terraform apply
```

[test/terraform/main.tf](../test/terraform/main.tf) is a fuller example
covering VPC, ECS, OBS and RDS.

## Go SDK

[huaweicloud-sdk-go-v3](https://github.com/huaweicloud/huaweicloud-sdk-go-v3)
does not read `HTTPS_PROXY`, so set the proxy in code:

```go
hc := config.DefaultHttpConfig().
	WithIgnoreSSLVerification(true). // or trust ~/weistack-ca.pem in your transport
	WithProxy(config.NewProxy().WithSchema("http").WithHost("127.0.0.1").WithPort(8780))

auth := basic.NewCredentialsBuilder().
	WithAk("any-access-key").
	WithSk("any-secret-key").
	WithProjectId(projectID). // from /_weistack/services
	Build()

client := vpc.NewVpcClient(vpc.VpcClientBuilder().
	WithEndpoints([]string{"https://vpc.ap-southeast-1.myhuaweicloud.com"}).
	WithCredential(auth).
	WithHttpConfig(hc).
	Build())
```

## OBS SDK for Go

[huaweicloud-sdk-go-obs](https://github.com/huaweicloud/huaweicloud-sdk-go-obs)
can trust the CA directly:

```go
caPEM, _ := os.ReadFile(filepath.Join(home, "weistack-ca.pem"))
client, err := obs.New("any-access-key", "any-secret-key", "https://obs.ap-southeast-1.myhuaweicloud.com",
	obs.WithProxyUrl("http://127.0.0.1:8780"),
	obs.WithSslVerifyAndPemCerts(true, caPEM),
	obs.WithSignature(obs.SignatureObs),
	obs.WithRegion("ap-southeast-1"),
)
```

Virtual-hosted buckets (`my-bucket.obs.ap-southeast-1.myhuaweicloud.com`)
need no DNS set-up: the proxy sees the bucket in the host name.

## AWS CLI and S3 SDKs

OBS is S3-compatible. Point the client at the `/obs` path prefix and use
path-style addressing, since there is no DNS for virtual-hosted buckets:

```bash
aws configure set default.s3.addressing_style path
export AWS_ACCESS_KEY_ID=any-access-key AWS_SECRET_ACCESS_KEY=any-secret-key AWS_DEFAULT_REGION=ap-southeast-1
aws --endpoint-url http://127.0.0.1:8780/obs s3 mb s3://my-bucket
aws --endpoint-url http://127.0.0.1:8780/obs s3 cp ./file.txt s3://my-bucket/file.txt
aws --endpoint-url http://127.0.0.1:8780/obs s3 ls s3://my-bucket
```

The region must be the emulator's: OBS rejects a bucket whose location
does not match the endpoint, as the real service does. In an SDK, set the
base endpoint to `http://127.0.0.1:8780/obs` and enable path style (for
example `UsePathStyle` in the AWS SDK for Go v2, or
`s3={"addressing_style": "path"}` in boto3).

## Python SDK

[huaweicloud-sdk-python-v3](https://github.com/huaweicloud/huaweicloud-sdk-python-v3)
takes the proxy and TLS settings in `HttpConfig`:

```python
import os

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkvpc.v2 import VpcClient, ListVpcsRequest
from huaweicloudsdkvpc.v2.region.vpc_region import VpcRegion

config = HttpConfig.get_default_config()
config.proxy_protocol = "http"
config.proxy_host = "127.0.0.1"
config.proxy_port = 8780
config.ssl_ca_cert = os.path.expanduser("~/weistack-ca.pem")  # or: config.ignore_ssl_verification = True

credentials = BasicCredentials("any-access-key", "any-secret-key", project_id=project_id)
client = (VpcClient.new_builder()
          .with_credentials(credentials)
          .with_region(VpcRegion.value_of("ap-southeast-1"))
          .with_http_config(config)
          .build())
print(client.list_vpcs(ListVpcsRequest()))
```

Give the `project_id` explicitly. Without it the SDK asks IAM for one, and
WeiStack does not emulate IAM.

## OBS SDK for Python

[esdk-obs-python](https://github.com/huaweicloud/huaweicloud-sdk-python-obs):

```python
import os

from obs import ObsClient

client = ObsClient(
    access_key_id="any-access-key",
    secret_access_key="any-secret-key",
    server="https://obs.ap-southeast-1.myhuaweicloud.com",
    proxy_host="127.0.0.1",
    proxy_port=8780,
    ssl_verify=os.path.expanduser("~/weistack-ca.pem"),  # a path trusts that CA
    signature="obs",
    is_signature_negotiation=False,
)
```

`is_signature_negotiation=False` and `signature="obs"` skip the probe
requests the SDK otherwise makes to choose a signature, which only matter
against the real service.

## KooCLI

[KooCLI](https://support.huaweicloud.com/intl/en-us/usermanual-hcli/hcli_22_001.html)
(`hcloud`) reads the lowercase proxy variables. It has no option to trust a
CA, so it must skip certificate verification:

```bash
export https_proxy=http://127.0.0.1:8780
hcloud VPC ListVpcs --cli-region=ap-southeast-1 --project_id=$PROJECT \
  --cli-access-key=any-access-key --cli-secret-key=any-secret-key \
  --cli-skip-secure-verify=true
```

Through the proxy, KooCLI can still download its API metadata from Huawei
Cloud: by default WeiStack passes requests for other hosts through for
clients on your machine.
