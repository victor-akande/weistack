# Threat model

What WeiStack protects, from whom, and what it leaves to you. It is a
development emulator: the aim is that running it does not make your
machine or your network less safe, not that it be as hard to break as a
cloud.

## What is worth protecting

- **The data** under `-persist` (`-data-dir`): every resource, object
  bodies, the account, and the vault key that seals stored secret keys
  and KMS key material (unless `-vault-key-file` keeps it elsewhere).
- **The local CA's key** (`-tls-dir`, `ca-key.pem`): clients that trust
  the CA accept the certificates it signs.
- **The administrator's keys** (`admin-credentials.json` beside the CA,
  or `-admin-access-key`).
- **The machine and the network** around WeiStack: its disk and memory,
  and the hosts its proxy could reach.

## Who might attack, and what stops them

**Web pages you visit.** A browser lets any page send requests to
`127.0.0.1`.

- The admin API refuses requests a browser sends from a page on another
  site (`Origin` or `Sec-Fetch-Site`), so no page can wipe the data,
  dump it or create accounts.
- While WeiStack listens only on loopback, it answers only `localhost`,
  IP addresses, the proxy domains and `-allowed-hosts`, so a page cannot
  reach it through DNS rebinding.

**Other users of the machine.**

- WeiStack listens on loopback by default, and outside a container it
  refuses `-host` addresses beyond it.
- Its files are readable only by you: the data, the vault key, the CA
  key and the administrator's keys.
- It refuses a data directory other users can write to.

**Clients on your network (`-lan`).** Off by default.

- The `-lan` port speaks only HTTPS, with the local CA.
- It admits only private, shared and loopback addresses, or `-lan-clients`.
- It checks every request's credentials and permissions as
  `-iam=enforce` does, whatever `-iam` says.
- Its admin API answers only the administrator, and never dumps or wipes
  the data.
- It tunnels to other hosts only for clients on WeiStack's own machine.

**Clients that use WeiStack's APIs**, with or without valid credentials.

- Under `-iam=enforce`, every request needs a valid signature or token
  and the permissions for its operation, and the admin API answers only
  the administrator.
- Quotas limit what each project holds.
- `-max-data-bytes` caps the data on disk or in memory, and
  `-max-body-bytes` caps JSON request bodies.

**Files you are handed.**

- `weistack restore` writes only regular files, inside a directory that
  was missing or empty.
- It refuses archives of a newer format.
- A failed restore leaves nothing behind.

**Whoever obtains the CA key.** A CA created since v0.3 can sign only
for `myhuaweicloud.com` and the proxy domains it was created with,
`localhost`, `.local`, `.lan`, `.internal` and `.home.arpa` names, and
loopback and private addresses. Clients refuse any other certificate it
signs.

**Tampered releases.**

- Releases carry signed provenance attestations (see
  [SECURITY.md](../SECURITY.md#verifying-a-release)).
- The GitHub Action checks `checksums.txt`.
- Builds pin every action by commit and every base image by digest.
- Dependabot, govulncheck, CodeQL and fuzzing watch the code and its
  dependencies.

## What WeiStack does not protect against

- **Anyone who reaches it under `-iam=accept`** (the default). Any
  credentials work, so whoever reaches the port can do anything the APIs
  allow. On loopback that is you and your processes. Service APIs answer
  every origin (`Access-Control-Allow-Origin: *`), so **a web page you
  visit can also call them** on `127.0.0.1`: create, change and delete
  resources and objects, though not use the admin API. Use
  `-iam=enforce` if that matters to you.
- **A published container port.** Inside a container WeiStack must bind
  every interface. Publishing the port on all interfaces (`-p 8780:8780`)
  exposes plain HTTP without the `-lan` checks. Publish it on loopback,
  `-p 127.0.0.1:8780:8780`, as the README and `docker-compose.yml` do.
- **Your own account on the machine.** Whoever can act as you can read
  the data, the vault key and the CA key, as with any program's files.
- **A CA created before v0.3**, which has no name constraints. WeiStack
  warns at start; replace it as the README says.
- **Gaps in emulated authentication.** WeiStack checks only the
  signature algorithms listed in [Checking credentials](enforce.md). For
  uploads signed with trailing headers it checks the request's signature,
  not each chunk's. Agency tokens and federation are not emulated.
- **Denial of service on the machine itself.** Request rates are not
  limited, and the data limit is checked per write, not under one lock,
  so it can be exceeded by about one write per concurrent client.
- **The real cloud.** WeiStack never contacts Huawei Cloud. Treat any
  real credentials you use with it as exposed.

## Reporting

See [SECURITY.md](../SECURITY.md).
