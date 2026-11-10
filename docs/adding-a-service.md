# Adding a service

Every emulated service follows the same shape. This page describes the
contract the core framework gives you; `internal/server/server_test.go` has a
minimal fake service you can read alongside it.

## Layout

```
internal/services/<name>/
  api.go            handlers and routes
  models.go         request/response types, copied from the official SDK models
  service.go        business rules: validation, state machines, dependency checks
  errors.go         the service's error catalogue (code, HTTP status, message)
  service_test.go   unit tests for the rules
  api_test.go       HTTP-level tests against golden files
```

## 1. Implement `server.Service`

```go
type Service interface {
    Name() string          // endpoint label and path prefix, e.g. "vpc"
    Version() string       // e.g. "v1, v3"
    Routes(r chi.Router)   // register handlers on the real API paths
}
```

Register paths exactly as the real API has them (`/v1/{project_id}/vpcs`). The
server strips the `/{name}` prefix for path-style requests, so a handler never
needs to know how it was reached.

Optional interfaces:

- `server.Resetter`: re-seed state (public images, flavors) after
  `POST /_weistack/reset`.
- `server.BodyLimiter`: override the JSON body limit; return `0` for
  unlimited (OBS uploads).

Then construct the service in `buildServices` in `internal/app/app.go`.

Some APIs do not put the project ID in the path (IMS, for example). Take it
from `auth.FromContext(ctx).ProjectID`, the `X-Project-Id` header the SDKs
send, and fall back to the emulator's default project.

## 2. Use the core packages

| Need | Package | Notes |
| --- | --- | --- |
| Store resources | `core/store` | `store.Of[T](s, store.Scope{Region, ProjectID, Kind})`; `Update` is an atomic read-modify-write |
| Delayed transitions | `core/lifecycle` | `engine.Schedule(lifecycle.Task{Key: id, Kind: "ecs.server.build", Run: ...})`; `engine.Cancel(id)` on delete |
| IDs | `core/ids` | `UUID()` for resources, `Hex32()` for jobs |
| Errors | `core/apierr` | `apierr.Write(w, r, style, err)` with the service's envelope style |
| Paging | `core/pagination` | `ParseMarker`/`ByMarker`, `ParseOffset`/`ByOffset` |
| JSON | `core/httpx` | `DecodeJSON`, `WriteJSON` |
| Request metadata | `core/reqctx` | `reqctx.From(ctx).Region`; call `SetOperation("CreateVpc")` so logs name the operation |
| Caller identity | `core/auth` | `auth.FromContext(ctx)` |

Rules that keep the emulator correct under load:

- A callback passed to `Update` may run more than once. Keep it free of side
  effects; allocate IDs and schedule lifecycle tasks outside it.
- Lifecycle tasks run on one shared goroutine. Do a store update and return;
  never block.
- Region comes from `reqctx`, project from the URL. Never read state outside
  the request's scope.

## 3. Definition of done for an operation

1. Request and response types match the SDK model, field for field.
2. A golden-file HTTP test covers success and every documented error.
3. Service rules have table-driven unit tests.
4. An SDK integration test exercises it through the official client.
5. The operation is listed in the service's coverage table under `docs/`.

Anything not implemented must fall through to the default handler, which
returns `501 WeiStack.0501` naming the operation.
