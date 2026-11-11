# SDK-driven tests

These tests drive a real WeiStack process with Huawei Cloud's official Go
SDK. They are the third test layer of the project: where the HTTP tests
compare our responses with golden files, these prove that a real client can
build its requests, sign them, and decode our responses and errors.

```bash
make test-sdk
```

The suite is a separate Go module so the SDK (hundreds of megabytes of
generated code) never becomes a dependency of the emulator.

By default it builds the emulator from this repository and starts it on a
free port. To test an emulator that is already running, such as the Docker
image:

```bash
WEISTACK_ADDR=127.0.0.1:8780 WEISTACK_PROJECT_ID=<its project id> make test-sdk
```

`TestPersistenceAcrossRestarts` starts emulators of its own with
`-persist`, so it is skipped when `WEISTACK_ADDR` names an existing one. It
stops one in the middle of server and database creation and of a multipart
upload, and checks that everything finishes after the restart. It also
kills one and checks that acknowledged writes survived. The CI `image` job
checks the same for a container restarted with its `/data` volume.

## Adding a test

Every operation an emulated service supports must be called at least once
here, through the SDK's own client and request types, on both its success
path and its main error paths. Use `wantError` to assert the HTTP status and
Huawei error code as the SDK decodes them.
