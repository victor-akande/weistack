# Architecture

How WeiStack is put together: what happens to a request, what each package
does, and the rules that keep the emulator faithful to Huawei Cloud. For
adding a service step by step, see [Adding a service](adding-a-service.md).

## The idea

WeiStack is one Go binary that answers Huawei Cloud's real HTTP APIs, so
Huawei's SDKs, the Terraform provider, KooCLI and S3 tools work against it
unchanged. Two principles shape everything:

- **Fidelity.** Paths, request and response shapes (field for field with the
  official SDK models), status codes, error codes and asynchronous
  behaviour match the real service. Where WeiStack knowingly differs, the
  difference is documented on the service's page.
- **Compatibility.** The default mode accepts any credentials, as v0.1 did.
  Stricter behaviour, such as checking signatures (`-iam=enforce`), is
  opt-in.

## Layout

```
cmd/weistack/          flags, subcommands (ca, credentials, version), main
internal/app/          wiring: config → store → identity → services → server
internal/server/       the listener: routing, proxy, admin API, middleware,
                       credential enforcement
internal/core/         shared building blocks (below)
internal/services/     one package per emulated service
internal/tlsca/        the CA and leaf certificates for proxy mode
internal/testutil/     golden-file helpers
test/sdk/              tests driven by Huawei's official Go SDK (own module)
test/terraform/        a real provider run: apply, re-plan, destroy
test/perf/             performance budgets (build tag perf)
```

`internal/app` builds everything in order. `buildServices` in
`internal/app/app.go` constructs every service and passes them to
`server.New`, which mounts the enabled ones.

## The life of a request

```
client ──► listener (8780, also [::1])
             │
             ├─ CONNECT to *.myhuaweicloud.com ─► TLS with WeiStack's CA ─┐
             │                                                            │
             ▼                                                            ▼
        middleware chain: request ID → logging and metrics → panic recovery → CORS → credentials
             │
             ▼
        route()
             ├─ /_weistack/...                     → admin API
             ├─ Host vpc.ap-southeast-1.myhuaweicloud.com
             │  or ecs.localhost, iam.myhuaweicloud.com → service by host
             ├─ /vpc/v1/...                        → service by path prefix
             └─ anything else                      → 404 APIGW.0101
             │
             ▼
        dispatch(): body size limit → (-iam=enforce) verify the signature or token
             │
             ▼
        the service's chi router, on the real API path
```

- **Proxy mode** (`internal/server/proxy.go`). Clients set `HTTPS_PROXY`
  and keep the real endpoints. A `CONNECT` to an emulated domain is
  answered with a certificate from WeiStack's CA, and the decrypted requests
  enter the same chain. Other hosts are tunnelled or refused according to
  `-proxy-passthrough`, `-proxy-domains` and `-proxy-bypass`. No request
  can reach the real cloud for an emulated domain.
- **Routing** (`internal/server/routing.go`). A host label names a service
  only when a region, `localhost`, or the two labels of a domain follow it,
  so a bucket called `vpc` is not mistaken for the VPC service. Path-prefix
  requests have `/{service}` stripped, so handlers always see the real API
  path.
- **Middleware** (`internal/server/middleware.go`). Each request gets an ID
  (returned in `X-Request-Id`), its place in a W3C trace (`traceparent`
  in, `traceresponse` out) and a `reqctx.Info` that routing, handlers
  and logs share: region, service and operation. `auth.Middleware` parses
  the credentials and resolves the access key to a principal.
- **Enforcement** (`internal/server/enforce.go`, `enforce_obs.go`). Only
  with `-iam=enforce`: the signature (SDK-HMAC-SHA256, OBS/AWS v2, SigV4
  with presigned URLs and aws-chunked chunks) or IAM token must be valid,
  with the errors Huawei documents. The algorithms are in
  `internal/core/sigcheck`. See [Checking credentials](enforce.md).
- **Unknown operations** fall through to `501 WeiStack.0501`, naming the
  operation, so a gap in the emulator is never mistaken for real behaviour.

## Services

A service implements `server.Service`:

```go
type Service interface {
    Name() string        // endpoint label and path prefix: "vpc"
    Version() string     // "v1, v3"
    Routes(r chi.Router) // handlers on the real API paths
}
```

It may also implement `server.Resetter` (re-seed after
`POST /_weistack/reset`) and `server.BodyLimiter` (OBS lifts the body
limit for uploads). A service package usually has `api.go` (routes and
handlers), `models.go` (types copied from the SDK models), `service.go`
(rules and state machines), `errors.go` (the service's documented error
codes) and tests with golden files.

Services may depend on each other through small interfaces wired in
`buildServices`, never by reaching into another package's state: ECS asks
VPC for subnets and ports and IMS for images; VPC shows ECS NICs as ports;
EVS shows ECS disks.

## Core packages

| Package | What it does |
| --- | --- |
| `apierr` | Errors with a status and a service code, rendered in the service's envelope: `StyleFlat` (`error_code`/`error_msg`), `StyleNested` (ECS), `StyleCodeMessage` (VPC v1), `StyleFlatRequestID` (VPC v3, API gateway), `StyleXML` (OBS). Emulator-only codes are `WeiStack.0500` and `WeiStack.0501` |
| `store` | Versioned records in scopes `region/project/kind` (`_/_/kind` for global records), in memory or in a bbolt file. `store.Of[T]` gives a typed collection; `Update` is an atomic read-modify-write |
| `lifecycle` | Delayed state transitions (BUILD → ACTIVE, job → SUCCESS) on one goroutine and a timer heap. `Cancel(key)` drops a resource's pending tasks; a `FaultInjector` can make transitions fail |
| `reqctx` | Per-request region, service and operation |
| `auth` | Parses credentials from any supported scheme into an `Identity`; `FromContext` gives it to handlers |
| `identity` | The account (Huawei's domain), per-region projects, the bootstrap administrator and the key `Directory` (key → principal, secrets, lockout) |
| `sigcheck` | Signature verification for every scheme a default client sends |
| `vault` | AES-256-GCM sealing of secrets at rest |
| `ids` | Resource UUIDs, 32-hex job IDs, access keys |
| `pagination` | Marker and offset paging, as each API documents it |
| `httpx` | JSON decoding and encoding |
| `config` | Every flag and its `WEISTACK_*` environment variable |
| `wiretime`, `zones`, `hostpattern` | Huawei's time formats, availability zones, host matching |

## State

- **Scopes.** Every record lives in a scope: region, project and kind. A
  handler reads the region from `reqctx` and the project from the URL (or
  `X-Project-Id`, then the default project, for APIs without one in the
  path), and never reads outside that scope.
- **Records.** A value is a 16-byte header (creation sequence and version)
  followed by JSON. The version makes `Update` safe: its callback may run
  more than once, so it must not have side effects. Allocate IDs and
  schedule lifecycle tasks outside it.
- **Persistence.** With `-persist`, records go to `weistack.db` (bbolt) in
  the data directory and OBS object bodies to `objects/`; without it,
  everything is in memory and object bodies use a temporary directory.
- **Upgrades.** The data file records its format version. An older file is
  backed up and migrated; a file from a newer release is refused. Fixtures
  written by every released binary are opened by
  `internal/app/upgrade_test.go`.

## Asynchronous behaviour

Resources that take time on Huawei Cloud take time here: a new server is
`BUILD` and becomes `ACTIVE` after `-lifecycle-delay`, and job APIs report
`RUNNING` then `SUCCESS`. Lifecycle tasks run on one shared goroutine, so a
task does one store update and returns; it never blocks. Deleting a resource
cancels its pending tasks.

## Identity

The emulator has a primary account with an ID and a name, and one
project per region (the default region keeps the configured project ID).
More accounts can be added through the admin API; IAM keeps their records
apart and requests act in the caller's account. A bootstrap
administrator key pair is generated on first start and kept beside the CA;
`weistack credentials` prints it. IAM users' access keys are registered in
the key `Directory` when they are created, and their secrets are sealed by
the vault. Temporary credentials are not registered: their security
token is their claims sealed by the vault, which IAM opens on each request
(`auth.TemporaryResolver`). In the default mode an unknown key still works
and acts as its own owner, as in v0.1; with `-iam=enforce` it is refused.

## The admin API

`/_weistack/services`, `state`, `reset`, `ca`, `health`, `metrics` and
`accounts` serve the emulator itself. They are not Huawei APIs and are not protected by
`-iam`.

## Testing

| Layer | Where | What it proves |
| --- | --- | --- |
| Unit | `*_test.go` beside the code | rules, state machines, parsing |
| HTTP and golden files | `api_test.go`, `testdata/golden/` | exact response bodies for success and every documented error |
| SDK | `test/sdk` | Huawei's official Go SDK (and the OBS SDK and aws-sdk-go-v2) works against a real binary, with and without `-iam=enforce` |
| Terraform | `test/terraform` | the provider applies, re-plans with no changes, destroys and leaves nothing behind, through the proxy |
| Performance | `test/perf` | cold start under 1 s, idle memory under 50 MB, p99 under 10 ms |
| Upgrades | `internal/app/testdata/upgrade` | data from every release still opens |

`make check` runs what CI's test job runs. Tests always use temporary data
and TLS directories, never the user's.
