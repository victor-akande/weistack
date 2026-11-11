# WeiStack

[![CI](https://github.com/victor-akande/weistack/actions/workflows/ci.yml/badge.svg)](https://github.com/victor-akande/weistack/actions/workflows/ci.yml)

A lightweight, local emulator of core Huawei Cloud services, written in Go and
shipped as a single binary and Docker image. Point Huawei's own tools (KooCLI,
the official SDKs, the Terraform provider) at it with an endpoint override.

WeiStack is an independent project. It is not affiliated with, endorsed by, or
sponsored by Huawei.

## Status

Early development. The **core framework** (M1) and **VPC** (M2) are in
place, and so are **IMS** (M3), **ECS** (M4), **OBS** (M5) and **RDS**
(M6). Per-service coverage tables: [VPC](docs/services/vpc.md),
[IMS](docs/services/ims.md), [ECS](docs/services/ecs.md),
[OBS](docs/services/obs.md), [RDS](docs/services/rds.md), and the read-only
[EVS](docs/services/evs.md) view of server disks.

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
that. When WeiStack runs in a container, clients reach it from another
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
| `-proxy-passthrough` | `WEISTACK_PROXY_PASSTHROUGH` | `loopback` | Which proxy clients may reach other hosts: `loopback`, `all` or `none` |
| `-tls-dir` | `WEISTACK_TLS_DIR` | see above | Where the local CA is kept |
| `-metrics` | `WEISTACK_METRICS` | off | Serve Prometheus metrics |
| `-max-body-bytes` | `WEISTACK_MAX_BODY_BYTES` | `10485760` | Body limit for JSON APIs |
| `-shutdown-timeout` | `WEISTACK_SHUTDOWN_TIMEOUT` | `10s` | Drain time on SIGTERM |

## Admin API

| Endpoint | Purpose |
| --- | --- |
| `GET /_weistack/health` | Liveness and version |
| `GET /_weistack/services` | Enabled services, default region and project ID |
| `GET /_weistack/state` | Dump of every stored resource as JSON |
| `POST /_weistack/reset` | Wipe all state and pending transitions |
| `GET /_weistack/ca` | The proxy's CA certificate, as PEM |
| `GET /_weistack/metrics` | Prometheus metrics (only with `-metrics`) |

## Authentication

Not verified yet: any access key, signature or token is accepted. Credentials
are still parsed (and the access key logged at debug level) so real clients
work unchanged. Signature verification is planned for v0.2.

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
