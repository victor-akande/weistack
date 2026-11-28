# Data written by each release

`TestUpgradeFromReleasedData` starts the current code on these data
directories and reads every resource back, so an upgrade from any
released version is tested. `TestNewerDataIsRefused` checks the other
direction: data from a newer release is refused and left untouched.

Each `v<version>/data` directory was written by **that release's own
binary**, downloaded from the GitHub release and verified against its
`checksums.txt`, by `generate.sh <version>`. It starts the release as a user
would, with `-persist` and no `-project-id` (so the `project_id` file is
written too), and creates through the HTTP API:

- a VPC, a subnet, and a security group with an SSH rule
- an ECS server in them, and a private image of that server
- an OBS bucket with an object, owned by the access key `AKFIXTURE`
- an RDS MySQL instance

From v0.3.0 it also creates:

- an IAM user with a permanent access key, and a KMS key with a text it
  encrypted, so the test proves both still unseal: it signs a request
  with the key under `-iam=enforce` and decrypts the text
- an EIP, a public NAT gateway with an SNAT rule using it
- a dedicated load balancer with a listener, a pool and a member (the
  server)
- an EVS data disk attached to the server, and a snapshot of it

From v0.4.0 it also creates:

- two KPS key pairs whose private keys WeiStack keeps: one sealed by the
  vault key, one by the KMS key. The test exports each private key and
  checks it still matches the fingerprint in `ids.json`, which never holds
  the private keys
- a CSMS secret, which the test reads back

`ids.json` records their IDs for the test. The CA goes to a scratch
directory and is not committed: v0.1.0 kept it in the data directory, and
its private key does not belong in the repository. The RDS password is
random and WeiStack keeps no copy of it. From v0.3.0, `ids.json` holds the
fixture user's access key and secret key: they were made by the emulator
for the fixture, mean nothing anywhere else, and the test needs them.
From v0.2.0 the data directory also holds `vault-key.json`, the key that
seals secrets in the store, and `account.json`, the account's ID and name.
The key was generated for the fixture and seals nothing in it, since the
fixture holds no access keys or KMS keys; it is kept because the fixture
must stay exactly what the release wrote.

**After every release**, add its fixture:

```bash
internal/app/testdata/upgrade/generate.sh 0.1.2
```

Fixtures are never regenerated: each must stay what its release wrote.

**Before a release**, rehearse with a local build, outside the
repository, and run the test on the result:

```bash
make build
WEISTACK_FIXTURE_BINARY=bin/weistack WEISTACK_FIXTURE_OUT=/tmp/weistack-fixture \
  internal/app/testdata/upgrade/generate.sh 0.4.0
WEISTACK_UPGRADE_REHEARSAL=/tmp/weistack-fixture/data go test -run TestUpgradeFromReleasedData ./internal/app/
```
