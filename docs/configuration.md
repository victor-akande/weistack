# Configuration

Every setting is a flag or an environment variable. Flags take precedence
over environment variables, which take precedence over defaults.
`weistack -h` prints the full list.

```bash
weistack -persist -iam=enforce            # flags
WEISTACK_PERSIST=1 WEISTACK_IAM=enforce weistack   # the same, from the environment
```

## Flags

### Listening

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-host` | `WEISTACK_HOST` | `127.0.0.1` (`0.0.0.0` in the image) | Address to bind. The default also listens on `::1`. Addresses beyond loopback are refused outside a container (the image sets `WEISTACK_IN_CONTAINER=1`): use `-lan` |
| `-port` | `WEISTACK_PORT` | `8780` | Port to listen on |
| `-lan` | `WEISTACK_LAN` | off | Serve other machines over HTTPS on `-lan-port`, always checking credentials (see [Other machines](lan.md)) |
| `-lan-port` | `WEISTACK_LAN_PORT` | `8781` | The HTTPS port `-lan` opens on every interface |
| `-lan-clients` | `WEISTACK_LAN_CLIENTS` | private and loopback ranges | Address ranges `-lan` admits, for example `192.168.1.0/24` |
| `-service-ports` | `WEISTACK_SERVICE_PORTS` | none | Extra listeners that each serve one service, for example `obs=9000` |
| `-allowed-hosts` | `WEISTACK_ALLOWED_HOSTS` | none | Extra host names a loopback-bound WeiStack answers; `localhost`, IP addresses and the proxy domains always work, others are refused against DNS rebinding. `*` is one label |
| `-max-body-bytes` | `WEISTACK_MAX_BODY_BYTES` | `10485760` | Body limit for JSON APIs |
| `-shutdown-timeout` | `WEISTACK_SHUTDOWN_TIMEOUT` | `10s` | Drain time on SIGTERM |

### The cloud

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-region` | `WEISTACK_REGION` | `ap-southeast-1` | Region when a request names none |
| `-project-id` | `WEISTACK_PROJECT_ID` | generated | Default project, 32 hex characters |
| `-services` | `WEISTACK_SERVICES` | all | Comma-separated subset to enable |
| `-seed-dir` | `WEISTACK_SEED_DIR` | none | Directory of YAML files extending built-in seed data ([images](services/ims.md#adding-your-own), [flavors](services/ecs.md#adding-your-own)) |
| `-lifecycle-delay` | `WEISTACK_LIFECYCLE_DELAY` | `2s` | Duration of asynchronous transitions; `0` is instant |
| `-quotas` | `WEISTACK_QUOTAS` | a new Huawei account's | Per-project limits as `key=value,...`, `-1` unlimited, for example `vpc.vpc=500` (see [Quotas](quotas.md)) |
| `-ecs-max-servers` | `WEISTACK_ECS_MAX_SERVERS` | `20` | ECS server quota per project |
| `-ecs-max-vcpus` | `WEISTACK_ECS_MAX_VCPUS` | `80` | ECS vCPU quota per project |
| `-eip-max-per-project` | `WEISTACK_EIP_MAX_PER_PROJECT` | `50` | EIP quota per project |
| `-rds-max-instances` | `WEISTACK_RDS_MAX_INSTANCES` | `20` | RDS instance quota per project |

### Identity

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-iam` | `WEISTACK_IAM` | `accept` | `accept` takes any credentials; `enforce` requires a valid signature or IAM token, and permissions (see [Checking credentials](enforce.md)) |
| `-admin-access-key`, `-admin-secret-key` | `WEISTACK_ADMIN_ACCESS_KEY`, `WEISTACK_ADMIN_SECRET_KEY` | generated | Fix the administrator's keys, for example in CI. Prefer the environment variables for the secret: flags show in process lists |

### State

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-persist` | `WEISTACK_PERSIST` | off | Keep state on disk across restarts |
| `-data-dir` | `WEISTACK_DATA_DIR` | `~/.local/share/weistack` (`/data` in the image) | Where `-persist` keeps state and object data. macOS: `~/Library/Application Support/weistack`; Windows: `%LocalAppData%\weistack` |
| `-vault-key-file` | `WEISTACK_VAULT_KEY_FILE` | `vault-key.json` in `-data-dir` | With `-persist`, the key that seals stored secret keys and KMS key material, kept apart from the data. Move the existing file there; WeiStack refuses to start while a key is also left in the data directory |
| `-max-data-bytes` | `WEISTACK_MAX_DATA_BYTES` | `21474836480` (20 GiB) | Most data WeiStack keeps: records and object data, on disk or in memory. Past it, new resources and uploads get 507 `WeiStack.0507`; changes and deletes still work. `0` is no limit. Reset backups are not counted |

### Proxy and TLS

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-proxy-domains` | `WEISTACK_PROXY_DOMAINS` | `myhuaweicloud.com` | Domains the proxy answers for itself |
| `-proxy-bypass` | `WEISTACK_PROXY_BYPASS` | KooCLI's downloads and API Explorer | Hosts inside the proxy domains that are passed on instead of answered: `*` is one label, `{region}` the same label everywhere. Empty turns it off |
| `-proxy-passthrough` | `WEISTACK_PROXY_PASSTHROUGH` | `loopback` | Which proxy clients may reach other hosts: `loopback`, `all` or `none` |
| `-tls-dir` | `WEISTACK_TLS_DIR` | `~/.config/weistack/tls` (`/data/tls` in the image) | Where the local CA and the administrator's keys are kept |

### Logs and metrics

| Flag | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `-log-level` | `WEISTACK_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `-log-format` | `WEISTACK_LOG_FORMAT` | `auto` | `json`, `text`, or `auto`: text at a terminal, JSON otherwise |
| `-metrics` | `WEISTACK_METRICS` | off | Serve Prometheus metrics at `/_weistack/metrics` |

## Commands

| Command | What it does |
| --- | --- |
| `weistack` | Start the emulator |
| `weistack version` | Print the version |
| `weistack healthcheck` | Exit 0 if a running emulator is healthy, for container health checks |
| `weistack credentials` | Print the administrator's keys as `export` lines for the SDKs and Terraform: `eval "$(weistack credentials)"` |
| `weistack ca` | Print the local CA's certificate, and where it is kept |
| `weistack admin METHOD PATH [BODY]` | Call the admin API, signed with the administrator's keys, for example `weistack admin GET services` |
| `weistack backup [FILE]` | Archive the data directory, whether WeiStack is running on it or not; `-` writes to stdout |
| `weistack restore FILE` | Unpack an archive into an empty data directory |

Commands that talk to a running emulator or its data take the same flags
it was started with, such as `-data-dir` or `-port`.

## How requests are routed

One listener (default port `8780`) serves every service. A request is
matched, in order, by:

1. **Host header**, in Huawei's endpoint form
   `{service}.{region}.myhuaweicloud.com` (also `{bucket}.obs.{region}...`
   and, for convenience, `{service}.localhost`). The region in the host name
   scopes the request.
2. **Path prefix** `/{service}/...`, for clients that only accept a base
   URL. The prefix is stripped, so the service sees the real API path.

Anything else gets the API gateway's own `APIGW.0101` 404. An operation
that a service does not emulate yet returns `501` with code `WeiStack.0501`
and a message naming the operation, so a gap is never mistaken for a bug.

Clients that let you override endpoints can address WeiStack directly
instead of through the proxy:

| Client can set | Use | Example |
| --- | --- | --- |
| A full endpoint per service | Path prefix, or a host name that resolves to WeiStack | `http://127.0.0.1:8780/vpc` |
| Only a base URL, path kept | Path prefix | `http://localhost:8780/vpc` |
| A different port per service | `-service-ports` | `-service-ports obs=9000` |

`{service}.localhost` host names also route, but whether they resolve to
the loopback depends on the system resolver (it does not in WSL, for
example), so prefer the proxy. The official Go SDK discards any path in
its endpoint, so use the proxy or a dial override with it. See
[Connecting clients](clients.md) for each client.

## Admin API

| Endpoint | Purpose |
| --- | --- |
| `GET /_weistack/health` | Liveness and version |
| `GET /_weistack/services` | Enabled services, default region, project ID and account |
| `GET /_weistack/state` | Dump of every stored resource as JSON |
| `POST /_weistack/reset` | Wipe all state, pending transitions and injected faults; with `-persist`, after keeping a backup in `backups/` in the data directory |
| `GET /_weistack/backup` | A backup of the persisted data, as `.tar.gz` (only with `-persist`; `weistack backup` fetches it, and `weistack restore` restores it) |
| `GET /_weistack/ca` | The proxy's CA certificate, as PEM |
| `GET /_weistack/accounts` | Every account: the primary one and those added |
| `POST /_weistack/accounts` | Add an account, `{"name": "partner"}`; returns its root user's keys |
| `GET /_weistack/metrics` | Prometheus metrics (only with `-metrics`) |
| `GET`, `POST`, `DELETE /_weistack/faults` | List, add and clear injected faults; `DELETE /_weistack/faults/{id}` removes one (see [Injecting faults](faults.md)) |

Under `-iam=enforce`, and always over `-lan`, every endpoint but `health`
and `ca` needs the administrator's credentials. `weistack admin` signs the
call with them, for example `weistack admin POST reset` (see
[Checking credentials](enforce.md)). With `-iam=accept` the admin API is
open to anyone who can reach the port: keep it to yourself.

## Accounts and the administrator

WeiStack has a primary account (Huawei Cloud's "domain") and an
administrator. More accounts can be added through the admin API, to try
what one account may do in another (see
[IAM: accounts](services/iam.md#accounts)).

The administrator's keys are generated on first start and kept beside the
CA (`admin-credentials.json` in `-tls-dir`, readable only by you), so they
stay the same across restarts. The banner shows them, and
`weistack credentials` prints them.

`/_weistack/services` reports the account's ID and name. Keys WeiStack
knows, the administrator's and IAM users' (see
[IAM: access keys](services/iam.md#access-keys)), act for the account:
their OBS buckets belong to it, as on Huawei Cloud. So do temporary
credentials, with their security token (see
[IAM: temporary credentials](services/iam.md#temporary-credentials)):
another account that assumes one of the account's agencies acts in it.

With `-iam=accept`, signatures and tokens are parsed but not checked: any
access key and secret key work, and a key WeiStack does not know is an
owner of its own. With `-iam=enforce`, they are checked as Huawei Cloud
checks them; see [Checking credentials](enforce.md).
