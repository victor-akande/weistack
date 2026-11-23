# Security policy

WeiStack is a local emulator of Huawei Cloud for development and tests.
It is not a cloud, and it is not meant to hold real secrets or to face
the internet. Within that use, it should not let a web page, another
user of the machine, or a client on the network do more than the
[threat model](docs/threat-model.md) says, and should not lose or leak
the data it keeps. A way around either is a vulnerability.

## Supported versions

Fixes go into the latest release. While WeiStack is at 0.x, earlier
releases are not patched: upgrade instead. Data kept by any release
opens in every later one, so upgrading never strands it.

## Reporting a vulnerability

Report it privately through GitHub:
[Security > Report a vulnerability](https://github.com/victor-akande/weistack/security/advisories/new).
Please do not open a public issue.

Say what an attacker can do, from where (a web page, another local user,
the network with `-lan`, a crafted file), and how to reproduce it with
which release and flags. You will get an answer within a week. Once a
fix is released, the advisory is published with credit, unless you
prefer otherwise.

## Verifying a release

Every archive, `checksums.txt` and the image of releases since v0.3.0
carry a signed build provenance attestation, made by the release
workflow in this repository:

```bash
gh attestation verify weistack_0.3.0_linux_amd64.tar.gz --repo victor-akande/weistack
gh attestation verify oci://docker.io/victhedev/weistack:0.3.0 --repo victor-akande/weistack
```

`checksums.txt` lists every archive's SHA-256, which the
[GitHub Action](docs/github-action.md) checks before it runs a download.
