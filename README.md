# WeiStack

[![CI](https://github.com/victor-akande/weistack/actions/workflows/ci.yml/badge.svg)](https://github.com/victor-akande/weistack/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/victor-akande/weistack)](https://github.com/victor-akande/weistack/releases)
[![Docker image](https://img.shields.io/docker/image-size/victhedev/weistack/latest?label=image)](https://hub.docker.com/r/victhedev/weistack)
[![Licence](https://img.shields.io/github/license/victor-akande/weistack)](LICENSE)

**Huawei Cloud on your own machine.** WeiStack is a local emulator of core
Huawei Cloud services, for development, tests and CI. Huawei's own
Terraform provider, SDKs and KooCLI work against it unchanged: they keep
the real endpoints and reach WeiStack as an HTTPS proxy, so nothing you run
can reach the real cloud by mistake, and nothing costs money.

```bash
weistack                                 # start it
export HTTPS_PROXY=http://127.0.0.1:8780 # send Huawei Cloud's endpoints to it
terraform apply                          # your real configuration, unchanged
```

WeiStack is an independent project. It is not affiliated with, endorsed
by, or sponsored by Huawei.

## Contents

- [Why WeiStack](#why-weistack)
- [What it emulates](#what-it-emulates)
- [Quick start](#quick-start)
- [Connecting your tools](#connecting-your-tools)
- [Ways to run it](#ways-to-run-it)
- [Examples](#examples)
- [Documentation](#documentation)
- [Upgrades and your data](#upgrades-and-your-data)
- [Security](#security)
- [Contributing](#contributing)

## Why WeiStack

- **Your real tools, unchanged.** Terraform's `huaweicloud` provider, the
  Go and Python SDKs, the OBS SDKs, KooCLI and S3 tools speak to WeiStack
  exactly as they speak to Huawei Cloud. You test the code you ship.
- **It behaves like the cloud.** Resources move through the same states
  (`CREATING`, then `ACTIVE`), quotas start at a new Huawei account's
  defaults, and errors carry Huawei's documented codes and shapes. An
  operation WeiStack does not emulate answers `501 WeiStack.0501` and names
  itself, so a gap is never mistaken for a bug in your code.
- **Real identity, when you want it.** By default any credentials work.
  With `-iam=enforce`, every request must be signed with known keys and is
  allowed only what the caller's IAM permissions allow, with the denials
  Huawei returns. Users, groups, roles, policies, agencies, temporary
  credentials and KMS keys are all real.
- **Small and fast.** One static binary with no dependencies, for Linux,
  macOS and Windows on amd64 and arm64, and a multi-architecture Docker
  image of about 5 MB. CI checks on every change that it starts in under a
  second and idles in under 50 MB of memory.
- **Built for CI.** The repository is also a GitHub Action: one line gives
  a job a running WeiStack and credentials for every client.
- **Safe by default.** It listens only on loopback, never passes an API
  request on to the real cloud, and its local certificate authority can
  sign only for the names WeiStack answers.

## What it emulates

WeiStack emulates the **control plane**: the APIs that create, change,
list and delete resources. Every resource is tracked and reported as
Huawei Cloud would, but no virtual machine boots and no database serves
queries. OBS is the exception: objects are stored and served.

| Area | Service | What you get |
| --- | --- | --- |
| Compute | [ECS](docs/services/ecs.md) | Servers, flavors, actions (start, stop, reboot, resize), jobs, tags |
| | [IMS](docs/services/ims.md) | Public images, and private images of your servers |
| | [EVS](docs/services/evs.md) | Volumes, attachments, resizing and snapshots; every server disk is a volume |
| Networking | [VPC](docs/services/vpc.md) | VPCs, subnets, security groups and rules, ports |
| | [EIP](docs/services/eip.md) | Elastic IPs and shared bandwidths |
| | [NAT](docs/services/nat.md) | Public and private NAT gateways, SNAT and DNAT rules |
| | [ELB](docs/services/elb.md) | Dedicated load balancers: listeners, pools, members, health checks |
| Storage | [OBS](docs/services/obs.md) | Buckets, objects, multipart uploads, server-side encryption, over the OBS and S3 APIs |
| Database | [RDS](docs/services/rds.md) | MySQL and PostgreSQL instances |
| Security | [IAM](docs/services/iam.md) | Users, groups, access keys, tokens, roles, custom and IAM 5.0 policies, agencies, temporary credentials |
| | [STS](docs/services/iam.md#caller-identity) | Caller identity, authorization messages, assuming agencies |
| | [KMS](docs/services/kms.md) | Keys with real cryptography, data keys, rotation, grants, tags |
| | [KPS](docs/services/kps.md) | SSH key pairs, private key protection (vault or KMS), ECS association tasks |
| Management | [EPS](docs/services/eps.md) | The default enterprise project |

[Coverage](docs/coverage.md) lists every operation served, by service and
API version, with the IAM action that authorizes it. Each service's page
describes how it behaves and what it does not do yet.

## Quick start

**1. Install.** Download a binary from the
[releases](https://github.com/victor-akande/weistack/releases), or build
from source with `make build`. [Installing](docs/install.md) has each way,
with checksums.

**2. Start it.** At a terminal, WeiStack prints its address, the project
ID, and how to point clients at it:

```bash
weistack
```

Or run the image. As a proxy for the host, it needs
`WEISTACK_PROXY_PASSTHROUGH=all` to relay downloads such as Terraform's
providers (see [Installing](docs/install.md#the-docker-image)):

```bash
docker run -it --rm -p 127.0.0.1:8780:8780 \
  -e WEISTACK_PROXY_PASSTHROUGH=all victhedev/weistack:latest
```

**3. Point your tools at it**, in another terminal. Send Huawei Cloud's
endpoints through WeiStack, trust its certificate authority, and load the
administrator's keys:

```bash
export HTTPS_PROXY=http://127.0.0.1:8780
curl -s -o ~/weistack-ca.pem http://127.0.0.1:8780/_weistack/ca
export SSL_CERT_FILE=~/weistack-ca.pem
export HW_REGION_NAME=ap-southeast-1 HW_ACCESS_KEY=any HW_SECRET_KEY=any
export TF_VAR_project_id=$(curl -s http://127.0.0.1:8780/_weistack/services \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["project_id"])')
```

Any keys work by default. With `-iam=enforce`, load the administrator's
keys with `eval "$(weistack credentials)"`, and read the project ID with
`weistack admin GET services`, since the admin API then needs them too.

**4. Use it.** A Terraform configuration for Huawei Cloud needs only its
project ID and two settings that skip calls to the real cloud's website:

```hcl
terraform {
  required_providers {
    huaweicloud = { source = "huaweicloud/huaweicloud", version = "1.100.0" }
  }
}

variable "project_id" { type = string }

provider "huaweicloud" {
  project_id              = var.project_id
  skip_check_website_type = true
  skip_check_upgrade      = true
}

resource "huaweicloud_vpc" "app" {
  name = "app-vpc"
  cidr = "10.10.0.0/16"
}

resource "huaweicloud_obs_bucket" "assets" {
  bucket = "my-app-assets"
}
```

```bash
terraform init && terraform apply
terraform plan      # "No changes": WeiStack reports what was written
```

[Getting started](docs/getting-started.md) goes through the same steps
in more detail, with `curl` first and then keeping state across restarts.

## Connecting your tools

There are two ways to reach WeiStack:

- **As an HTTPS proxy (recommended).** Clients keep Huawei Cloud's real
  endpoints and send their traffic through WeiStack, which answers every
  host under `myhuaweicloud.com` itself. Nothing is configured per
  service, virtual-hosted OBS buckets work as in the cloud, and a service
  WeiStack does not emulate fails instead of reaching the real one.
- **By endpoint.** Clients that let you override endpoints but not set a
  proxy send plain HTTP to a path prefix, such as
  `http://127.0.0.1:8780/vpc`.

| Client | Set-up |
| --- | --- |
| Terraform (`huaweicloud` provider) | [Proxy](docs/clients.md#terraform) |
| Go SDK | [Proxy, set in code](docs/clients.md#go-sdk): it does not read `HTTPS_PROXY` |
| Python SDK | [Proxy](docs/clients.md#python-sdk) |
| OBS SDKs for Go and Python | [Proxy](docs/clients.md#obs-sdk-for-go) |
| AWS CLI and S3 SDKs | [Endpoint](docs/clients.md#aws-cli-and-s3-sdks) |
| KooCLI (`hcloud`) | [Proxy](docs/clients.md#koocli) |
| `curl` and scripts | Either |

[Connecting clients](docs/clients.md) has the exact set-up for each, and
how each one was checked.

## Ways to run it

The defaults suit one developer on one machine: everything in memory, any
credentials accepted, loopback only. Each of these changes one thing, and
they combine.

| You want to | Run | Read |
| --- | --- | --- |
| Keep state across restarts | `weistack -persist` | [Getting started](docs/getting-started.md#5-keep-state-across-restarts) |
| Check signatures and permissions as Huawei Cloud does | `weistack -iam=enforce` | [Checking credentials](docs/enforce.md) |
| Serve other machines on your network, over HTTPS | `weistack -lan` | [Other machines](docs/lan.md) |
| Test how your code handles failures and slow responses | `weistack admin POST faults ...` | [Injecting faults](docs/faults.md) |
| Hit a quota on purpose, or lift one | `weistack -quotas vpc.vpc=1` | [Quotas](docs/quotas.md) |
| See every resource and how they relate | `weistack admin GET inventory` | [Inventory](docs/inventory.md) |
| Back up and restore the data | `weistack backup`, `weistack restore` | [Getting started](docs/getting-started.md#5-keep-state-across-restarts) |
| Run it in a GitHub Actions job | `uses: victor-akande/weistack@v0.3.0` | [In GitHub Actions](docs/github-action.md) |
| Run it as a service for a team | the hardened systemd unit | [Web-app example, step 1](examples/web-app/README.md#1-the-cloud-machine-weistack-as-a-service) |

In a workflow:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: victor-akande/weistack@v0.3.0
    with:
      iam: enforce
  - run: terraform init && terraform apply -auto-approve
```

The action starts WeiStack for the rest of the job and exports the
proxy, the region, the project ID and the administrator's keys for
Terraform and the SDKs.

Every flag also has an environment variable, such as `WEISTACK_PERSIST=1`;
[Configuration](docs/configuration.md) lists them all, with the commands
and the admin API.

## Examples

- **[A production-style web app](examples/web-app/README.md):** a
  three-tier stack with load balancer, servers, database, bucket, NAT and
  encryption keys, deployed step by step on a WeiStack shared by a team,
  with IAM enforced. Each person uses a different tool: Terraform, `curl`,
  KooCLI, the Python and Go SDKs, the AWS CLI and the GitHub Action. The
  stack is then operated, broken, recovered, tested in CI and torn down.
  CI runs the whole guide on every change.
- **[The Terraform scenario](test/terraform):** the stack CI applies,
  re-plans and destroys on every change, with the provider settings
  WeiStack needs.

## Documentation

| Guide | What it covers |
| --- | --- |
| [Getting started](docs/getting-started.md) | From a fresh clone to Terraform creating resources, in ten minutes |
| [Installing](docs/install.md) | Release binaries, the Docker image, building from source, running as a service |
| [Connecting clients](docs/clients.md) | The set-up for each SDK and tool, and trusting WeiStack's CA |
| [Configuration](docs/configuration.md) | Every flag and environment variable, the commands, routing, and the admin API |
| [Checking credentials](docs/enforce.md) | `-iam=enforce`: signatures, tokens, permissions, and the errors |
| [Other machines](docs/lan.md) | `-lan`: serving your network over HTTPS |
| [Injecting faults](docs/faults.md) | Failing lifecycles and requests on purpose |
| [Quotas](docs/quotas.md) | Every limit, its default, and how to change it |
| [Inventory](docs/inventory.md) | Every resource and how they relate, in one call |
| [In GitHub Actions](docs/github-action.md) | The action's inputs, outputs and examples |
| [Coverage](docs/coverage.md) | Every operation served, with its IAM action |
| [Services](docs/services) | How each service behaves, and its gaps |
| [Architecture](docs/architecture.md) | How WeiStack is put together |
| [Threat model](docs/threat-model.md) | What WeiStack protects, and what it leaves to you |

## Upgrades and your data

Data kept with `-persist` by any release opens in every later release,
which upgrades it on start. CI checks this on every change against data
written by each released version's own binary. A release refuses data
written by a newer one and leaves it untouched, so going back never
damages it. Take a copy before upgrading with `weistack backup`.

Releases follow [semantic versioning](https://semver.org). Until 1.0, a
minor release can change behaviour to match Huawei Cloud more closely;
its release notes say what changed and what to do.

## Security

WeiStack is for development and tests, not for production data. It
listens only on loopback unless you ask for more, and `-lan` serves other
machines only over HTTPS, checking every request's credentials.
[The threat model](docs/threat-model.md) says what WeiStack protects and
what it leaves to you. Report vulnerabilities privately, as
[SECURITY.md](SECURITY.md) explains.

## Contributing

Issues and pull requests are welcome. Anywhere WeiStack knowingly behaves
differently from Huawei Cloud is a bug: please open an issue.
[CONTRIBUTING.md](CONTRIBUTING.md) describes the workflow and conventions,
[Architecture](docs/architecture.md) how the code fits together, and
[Adding a service](docs/adding-a-service.md) how a service plugs in.

```bash
make check           # formatting, vet, lint, and tests with the race detector
make test-sdk        # drive a real emulator with Huawei's official Go SDK
make test-terraform  # apply, re-plan and destroy a stack with the Terraform provider
make help            # every target
```

## Licence

[Apache-2.0](LICENSE). Huawei, Huawei Cloud and the names of its services
are trademarks of Huawei Technologies Co., Ltd., used here only to say
what WeiStack is compatible with.
