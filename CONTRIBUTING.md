# Contributing to WeiStack

## Workflow: GitHub flow

`main` is always releasable and is protected: nothing is pushed to it directly.

1. Branch from an up-to-date `main`. Name the branch `<type>/<short-topic>`,
   for example `feat/vpc-subnets` or `fix/ecs-job-status`.
2. Commit in small steps using [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(ecs): add batch stop`, `fix(vpc): reject overlapping subnets`.
   Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
3. Push early and open a pull request (draft is fine) so CI runs.
4. CI must be green and review threads resolved before merging.
5. Squash-merge. The pull request title becomes the commit on `main`, so it
   must also be a Conventional Commit. The branch is deleted on merge.

Releases are cut by tagging `main` (`vMAJOR.MINOR.PATCH`, semantic versioning).

## Local setup

Requirements: Go (version in `go.mod`), `make`, and optionally
[golangci-lint](https://golangci-lint.run/) v2 and Docker.

```bash
make check   # gofmt, vet, lint and tests with the race detector: what CI runs
make build   # binary in ./bin
make help    # every target
```

Code that parses what clients or files send (signatures, request
bodies, stored records, archives) has fuzz targets (`func FuzzX` in a
`_test.go` file). `make fuzz` runs each for `FUZZTIME` (10s by default);
CI runs them briefly on every change and for five minutes each night. A
failing input lands in the package's `testdata/fuzz/`, where `go test`
replays it from then on: commit it with the fix. Add a target when you
add such a parser.

## Code conventions

- Standard Go layout; application code lives under `internal/`.
- No global mutable state outside `main`; pass dependencies explicitly.
- `context.Context` is the first parameter of anything that does I/O or waits.
- Wrap errors with `%w`; compare with `errors.Is` / `errors.As`.
- Table-driven tests; all tests must pass with `-race`.
- **Limits in tests come from variables, never literals.** A test that
  checks a quota or a service limit sets it in a variable (with
  `quota.For` for quotas) or reads the service's constant, and derives
  every count and expected result from it: `limit := 10`, create
  `limit + 6`, want `limit` created and `6` refused. A test that creates
  more resources than a default quota allows, and is not about quotas,
  raises that quota from its own count, as in
  `"WEISTACK_QUOTAS=" + quota.Format(map[quota.Key]int{quota.VPCVPC: n})`.
  The one place Huawei's published defaults are written out is
  `internal/core/quota/quota_test.go`, which checks the table itself.

## Fidelity

WeiStack's job is to behave like Huawei Cloud. Any place where we knowingly
differ from the real service is a bug: open an issue labelled `fidelity`.
