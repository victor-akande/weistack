# WeiStack

[![CI](https://github.com/victor-akande/weistack/actions/workflows/ci.yml/badge.svg)](https://github.com/victor-akande/weistack/actions/workflows/ci.yml)

A lightweight, local emulator of core Huawei Cloud services, written in Go and
shipped as a single binary and Docker image. Huawei's own tools (KooCLI, the
official SDKs, the Terraform provider) use it unchanged: they keep the real
endpoints and reach WeiStack as an HTTPS proxy.

WeiStack is an independent project. It is not affiliated with, endorsed by, or
sponsored by Huawei.

## Status

Early development. The **core framework** (M1) and **VPC** (M2) are in
place, and so are **IMS** (M3), **ECS** (M4), **OBS** (M5) and **RDS**
(M6). Per-service coverage tables: [VPC](docs/services/vpc.md),
[IMS](docs/services/ims.md), [ECS](docs/services/ecs.md),
[OBS](docs/services/obs.md), [RDS](docs/services/rds.md), the read-only
[EVS](docs/services/evs.md) view of server disks, and [IAM](docs/services/iam.md)
discovery, so clients need no project or domain ID.

| Milestone | Scope | State |
| --- | --- | --- |
| M1 | Core framework: server, routing, errors, store, lifecycle, admin API, CI, image | Done |
| M2 | VPC: VPCs, subnets, security groups and rules | Done |
| M3 | IMS: images | Done |
| M4 | ECS: servers, flavors, jobs | Done |
| M5 | OBS: buckets, objects, multipart | Done |
| M6 | RDS: MySQL/PostgreSQL instances | Done |

## Quick start

```bash
make build
./bin/weistack
```

At a terminal it prints the project ID, the proxy setting and how to trust
its CA. Then, in another terminal:

```bash
curl http://localhost:8780/_weistack/health
```

[docs/getting-started.md](docs/getting-started.md) walks through the rest:
creating resources with `curl`, then with Huawei's Terraform provider, and
keeping state across restarts.

With Docker:

```bash
docker compose up --build
```

## Install

Each [release](https://github.com/victor-akande/weistack/releases) has
binaries for Linux, macOS and Windows on amd64 and arm64, with a
`checksums.txt`. They have no dependencies:

```bash
tar -xzf weistack_<version>_linux_amd64.tar.gz
./weistack version
```

The image is multi-architecture (linux/amd64 and linux/arm64) and about
5 MB:

```bash
docker run -it --rm -p 127.0.0.1:8780:8780 victhedev/weistack:latest
```

With `-it` WeiStack sees a terminal: it prints its banner with the project
ID and writes readable logs. Detached (`-d`), it logs JSON for log
collectors; add `-e WEISTACK_LOG_FORMAT=text` to read `docker logs` more
easily. Other things to know when running the image:

- **Keep state** across restarts with a volume:
  `-e WEISTACK_PERSIST=1 -v weistack-data:/data`. The project ID and the
  proxy's CA are kept there too, so clients keep working after
  `docker restart`.
- **As a proxy**, requests from the host reach the container from another
  address, not the loopback, so by default WeiStack refuses to relay them
  to hosts it does not emulate (such as Terraform's provider registry).
  Add `-e WEISTACK_PROXY_PASSTHROUGH=all`; publishing the port on
  `127.0.0.1` keeps other machines out. A refused request names this
  setting in its response.
- **The CA** is served by the running container:
  `curl -o weistack-ca.pem http://127.0.0.1:8780/_weistack/ca`.

Or build from source with `make build` (Go 1.26 or later).

## Releasing

Pushing a version tag such as `v0.1.0` runs
[.github/workflows/release.yml](.github/workflows/release.yml): GoReleaser
publishes the binaries and release notes as a GitHub Release, and the image
is built for both architectures and pushed to Docker Hub. That needs the
variable `DOCKERHUB_REPOSITORY` and the secrets `DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN` in the repository's Actions settings. `goreleaser release
--snapshot --clean` builds every archive locally without publishing.

After a release, add its data fixture for the upgrade test:
`internal/app/testdata/upgrade/generate.sh <version>` (see the README there).

## How requests are routed

One listener (default port `8780`) serves every service. A request is matched,
in order, by:

1. **Host header**, in Huawei's endpoint form `{service}.{region}.myhuaweicloud.com`
   (also `{bucket}.obs.{region}...` and, for convenience, `{service}.localhost`).
   The region in the host name scopes the request.
2. **Path prefix** `/{service}/...`, for clients that only accept a base URL.
   The prefix is stripped, so the service sees the real API path.

Anything else gets the API gateway's own `APIGW.0101` 404. An operation that
a service does not emulate yet returns `501` with code `WeiStack.0501` and a
message naming the operation, so a gap is never mistaken for a bug.

## Pointing a client at WeiStack

[docs/clients.md](docs/clients.md) has a set-up for each client: Terraform,
the Go and Python SDKs, the OBS SDKs, the AWS CLI and KooCLI.

### As an HTTPS proxy (recommended)

WeiStack is also an HTTP proxy. A client keeps Huawei Cloud's real
endpoints and sends its traffic through WeiStack, which answers for every
host under `myhuaweicloud.com` itself. Nothing needs DNS changes, no
service can leak to the real cloud by being left unconfigured, and
virtual-hosted OBS buckets work as they do in the cloud.

```bash
export HTTPS_PROXY=http://127.0.0.1:8780
```

For HTTPS, WeiStack presents certificates from a local certificate
authority it creates on first start. Either tell the client to skip
verification (most have an `insecure` option), or trust the CA:

```bash
./bin/weistack ca > weistack-ca.pem   # prints the certificate, and where it lives
export SSL_CERT_FILE=$PWD/weistack-ca.pem   # Go and OpenSSL-based clients
```

The CA is kept in `~/.config/weistack/tls` (`-tls-dir` changes it;
`/data/tls` in the image), with or without `-persist`, so clients trust it
once. Its key never leaves that directory and is readable only by you. A
running emulator also serves the certificate, which is the easy way to get
it out of a container:

```bash
curl -o weistack-ca.pem http://127.0.0.1:8780/_weistack/ca
```

Requests to hosts outside `myhuaweicloud.com` are relayed unchanged, but
only for clients on the loopback interface; `-proxy-passthrough` changes
that. The same goes for the few hosts under `myhuaweicloud.com` that
Huawei's tools download from before calling any API (KooCLI's metadata and
API Explorer's catalogue, see `-proxy-bypass`), so those tools start
normally. No API request is ever passed on. When WeiStack runs in a container, clients reach it from another
address, so either set `NO_PROXY` for the hosts they need directly or run
the container with `-proxy-passthrough all`.

The official Go SDK does not read `HTTPS_PROXY`; set it in code:

```go
hc := config.DefaultHttpConfig().
    WithIgnoreSSLVerification(true).
    WithProxy(config.NewProxy().WithSchema("http").WithHost("127.0.0.1").WithPort(8780))
client := vpc.NewVpcClient(vpc.VpcClientBuilder().
    WithEndpoints([]string{"https://vpc.ap-southeast-1.myhuaweicloud.com"}).
    WithCredential(credentials). // any AK/SK; project ID from /_weistack/services
    WithHttpConfig(hc).
    Build())
```

### By endpoint

Clients that let you override endpoints can address WeiStack directly:

| Client can set | Use | Example |
| --- | --- | --- |
| A full endpoint per service | Path prefix, or a host name that resolves to WeiStack | `http://127.0.0.1:8780/vpc` |
| Only a base URL, path kept | Path prefix | `http://localhost:8780/vpc` |
| A different port per service | `-service-ports` | `-service-ports obs=9000` |

`{service}.localhost` host names also route, but whether they resolve to
the loopback depends on the system resolver (it does not in WSL, for
example), so prefer the proxy. The official Go SDK discards any path in
its endpoint, so use the proxy or a dial override with it.

## Configuration

Flags take precedence over environment variables, which take precedence over
defaults. Run `weistack -h` for the full list.

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-host` | `WEISTACK_HOST` | `127.0.0.1` (`0.0.0.0` in the image) | Address to bind. The default also listens on `::1` |
| `-port` | `WEISTACK_PORT` | `8780` | Port to listen on |
| `-region` | `WEISTACK_REGION` | `ap-southeast-1` | Region when a request names none |
| `-project-id` | `WEISTACK_PROJECT_ID` | generated | Default project, 32 hex characters |
| `-persist` | `WEISTACK_PERSIST` | off | Keep state on disk across restarts |
| `-data-dir` | `WEISTACK_DATA_DIR` | `~/.local/share/weistack` (`/data` in the image) | Where `-persist` keeps state and object data. macOS: `~/Library/Application Support/weistack`; Windows: `%LocalAppData%\weistack` |
| `-seed-dir` | `WEISTACK_SEED_DIR` | none | Directory of YAML files extending built-in seed data ([images](docs/services/ims.md#adding-your-own), [flavors](docs/services/ecs.md#adding-your-own)) |
| `-ecs-max-servers` | `WEISTACK_ECS_MAX_SERVERS` | `20` | ECS server quota per project |
| `-ecs-max-vcpus` | `WEISTACK_ECS_MAX_VCPUS` | `80` | ECS vCPU quota per project |
| `-rds-max-instances` | `WEISTACK_RDS_MAX_INSTANCES` | `20` | RDS instance quota per project |
| `-lifecycle-delay` | `WEISTACK_LIFECYCLE_DELAY` | `2s` | Duration of async transitions; `0` is instant |
| `-log-level` | `WEISTACK_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `-log-format` | `WEISTACK_LOG_FORMAT` | `auto` | `json`, `text`, or `auto`: text at a terminal, JSON otherwise |
| `-services` | `WEISTACK_SERVICES` | all | Comma-separated subset to enable |
| `-service-ports` | `WEISTACK_SERVICE_PORTS` | none | Extra listeners that each serve one service, for example `obs=9000` |
| `-proxy-domains` | `WEISTACK_PROXY_DOMAINS` | `myhuaweicloud.com` | Domains the proxy answers for itself |
| `-proxy-bypass` | `WEISTACK_PROXY_BYPASS` | KooCLI's downloads and API Explorer | Hosts inside the proxy domains that are passed on instead of answered: `*` is one label, `{region}` the same label everywhere. Empty turns it off |
| `-proxy-passthrough` | `WEISTACK_PROXY_PASSTHROUGH` | `loopback` | Which proxy clients may reach other hosts: `loopback`, `all` or `none` |
| `-admin-access-key`, `-admin-secret-key` | `WEISTACK_ADMIN_ACCESS_KEY`, `WEISTACK_ADMIN_SECRET_KEY` | generated | Fix the administrator's keys, for example in CI. Prefer the environment variables for the secret: flags show in process lists |
| `-tls-dir` | `WEISTACK_TLS_DIR` | see above | Where the local CA is kept |
| `-metrics` | `WEISTACK_METRICS` | off | Serve Prometheus metrics |
| `-max-body-bytes` | `WEISTACK_MAX_BODY_BYTES` | `10485760` | Body limit for JSON APIs |
| `-shutdown-timeout` | `WEISTACK_SHUTDOWN_TIMEOUT` | `10s` | Drain time on SIGTERM |

## Admin API

| Endpoint | Purpose |
| --- | --- |
| `GET /_weistack/health` | Liveness and version |
| `GET /_weistack/services` | Enabled services, default region, project ID and account |
| `GET /_weistack/state` | Dump of every stored resource as JSON |
| `POST /_weistack/reset` | Wipe all state and pending transitions |
| `GET /_weistack/ca` | The proxy's CA certificate, as PEM |
| `GET /_weistack/metrics` | Prometheus metrics (only with `-metrics`) |

## Authentication

WeiStack accepts any credentials: signatures and tokens are parsed but not
checked, so any access key and secret key work.

It does have one account (Huawei Cloud's "domain") and an administrator.
The administrator's keys are generated on first start and kept beside the
CA (`~/.config/weistack/tls/admin-credentials.json`, readable only by you),
so they stay the same across restarts. The banner shows them, and
`weistack credentials` prints them for the SDKs and Terraform:

```bash
eval "$(./bin/weistack credentials)"
```

`/_weistack/services` reports the account's ID and name. Keys WeiStack
knows, today only the administrator's, act for the account: their OBS
buckets belong to it, as on Huawei Cloud. Any other key is, as before, an
owner of its own.
## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow (GitHub flow,
Conventional Commits) and [docs/adding-a-service.md](docs/adding-a-service.md)
for how a service plugs into the core.

```bash
make check      # gofmt, vet, golangci-lint, tests with the race detector
make test-sdk   # drive a real emulator with Huawei's official Go SDK
make test-terraform  # apply, re-plan and destroy a stack with the Terraform provider
```

The Terraform scenario ([test/terraform](test/terraform)) also shows the
provider settings WeiStack needs.

## Licence

[Apache-2.0](LICENSE)
