# In GitHub Actions

The repository is also a GitHub Action. It downloads a WeiStack release for
the runner (Linux, macOS or Windows, x64 or ARM64), checks it against the
release's checksums, starts it for the rest of the job and exports
credentials, so the SDKs and Terraform work in the next steps without
further set-up.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: victor-akande/weistack@v0.4.1
  - run: terraform apply -auto-approve
```

The action runs the release of its own tag: `@v0.4.1` runs WeiStack v0.4.1.
From a branch it runs the latest release, unless `version` says otherwise.

## What the next steps get

| Variable | Value |
| --- | --- |
| `HW_ACCESS_KEY`, `HW_SECRET_KEY` | The administrator's keys, for Terraform (the secret is masked in logs) |
| `HUAWEICLOUD_SDK_AK`, `HUAWEICLOUD_SDK_SK` | The same keys, for the SDKs |
| `HW_REGION_NAME`, `HW_PROJECT_ID` | The default region and project |
| `HTTPS_PROXY`, `HTTP_PROXY` | WeiStack's proxy, unless `proxy: false` |
| `NO_PROXY` | With the proxy: `127.0.0.1,localhost` added, so WeiStack's own address is reached directly |
| `WEISTACK_ENDPOINT` | WeiStack's address, `http://127.0.0.1:8780` |
| `WEISTACK_CA_FILE` | The local CA's certificate, to verify TLS through the proxy |

With the proxy set, clients keep Huawei Cloud's real endpoints and WeiStack
answers them; requests to other hosts are relayed unchanged. Clients either
skip TLS verification (Terraform's `insecure = true`) or trust
`WEISTACK_CA_FILE` (`curl --cacert`, with `--ssl-no-revoke` on Windows; Python's
`REQUESTS_CA_BUNDLE`).
See [clients](clients.md) for each client's set-up, including the Go
SDK, which does not read `HTTPS_PROXY`.

The same values are the action's outputs: `endpoint`, `region`,
`project-id`, `access-key`, `secret-key`, `ca-file` and `log-file`.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | the action's tag, or the latest release | The release to run, such as `v0.4.1` |
| `binary` | | A WeiStack binary already on the runner, instead of a download |
| `iam` | `accept` | `enforce` checks signatures and permissions (see [Checking credentials](enforce.md)) |
| `services` | all | Comma-separated services to enable |
| `region` | `ap-southeast-1` | The default region |
| `project-id` | generated | The default project ID, 32 hex characters |
| `port` | `8780` | The port, on 127.0.0.1 |
| `lifecycle-delay` | WeiStack's | How long asynchronous transitions take, such as `0s` |
| `proxy` | `true` | Export `HTTPS_PROXY` and `HTTP_PROXY` |
| `args` | | Further flags, such as `-persist` |
| `token` | `github.token` | The token used to download the release |

## Examples

Test with credentials enforced, so a client that signs wrongly fails as it
would in the cloud:

```yaml
- uses: victor-akande/weistack@v0.4.1
  with:
    iam: enforce
    lifecycle-delay: 0s
```

Inject a fault before a step, to see how the code under test copes with
throttling (see [Injecting faults](faults.md)):

```yaml
- uses: victor-akande/weistack@v0.4.1
  id: weistack
- run: |
    curl -fsS -X POST "${{ steps.weistack.outputs.endpoint }}/_weistack/faults" \
      -d '{"type": "request", "service": "vpc", "status": 429, "times": 2}'
- run: go test ./...
```

Show WeiStack's log when a job fails:

```yaml
- if: failure()
  run: cat "${{ steps.weistack.outputs.log-file }}"
```
