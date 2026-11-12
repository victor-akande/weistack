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

`ids.json` records their IDs for the test. The CA goes to a scratch
directory and is not committed: v0.1.0 kept it in the data directory, and
its private key does not belong in the repository. Nothing secret is stored:
the RDS password is random and WeiStack keeps no copy of it.

**After every release**, add its fixture:

```bash
internal/app/testdata/upgrade/generate.sh 0.1.2
```

Fixtures are never regenerated: each must stay what its release wrote.
