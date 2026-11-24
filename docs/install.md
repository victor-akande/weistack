# Installing WeiStack

WeiStack is one binary with no dependencies. Pick whichever way suits you.

## A release binary

Each [release](https://github.com/victor-akande/weistack/releases) has
archives for Linux, macOS and Windows (a `.zip`), on amd64 and arm64,
with a `checksums.txt` to verify them against:

```bash
VERSION=0.3.0   # the release you want
curl -LO https://github.com/victor-akande/weistack/releases/download/v$VERSION/weistack_${VERSION}_linux_amd64.tar.gz
curl -LO https://github.com/victor-akande/weistack/releases/download/v$VERSION/checksums.txt
sha256sum --ignore-missing -c checksums.txt
tar -xzf weistack_${VERSION}_linux_amd64.tar.gz
./weistack version
```

Move `weistack` to a directory on your `PATH`, such as `/usr/local/bin`.

## The Docker image

The image is multi-architecture (linux/amd64 and linux/arm64) and about
5 MB:

```bash
docker run -it --rm -p 127.0.0.1:8780:8780 victhedev/weistack:latest
```

With `-it` WeiStack sees a terminal: it prints its banner with the project
ID and writes readable logs. Detached (`-d`), it logs JSON for log
collectors; add `-e WEISTACK_LOG_FORMAT=text` to read `docker logs` more
easily. Other things to know when running the image:

- **Keep state** across restarts with a volume:
  `-e WEISTACK_PERSIST=1 -v weistack-data:/data`. The project ID, the
  administrator's keys and the proxy's CA are kept there too, so clients
  keep working after `docker restart`.
- **As a proxy**, requests from the host reach the container from another
  address, not the loopback, so by default WeiStack refuses to relay them
  to hosts it does not emulate (such as Terraform's provider registry).
  Add `-e WEISTACK_PROXY_PASSTHROUGH=all`; publishing the port on
  `127.0.0.1` keeps other machines out. A refused request names this
  setting in its response.
- **The CA** is served by the running container:
  `curl -o weistack-ca.pem http://127.0.0.1:8780/_weistack/ca`.
- **Health** is checked by the image itself (`weistack healthcheck` every
  30 seconds), so `docker ps` shows whether WeiStack is up.

[docker-compose.yml](../docker-compose.yml) in the repository runs a
persistent WeiStack built from source: `docker compose up --build`.

## From source

With Go (the version in [go.mod](../go.mod)) and Make:

```bash
git clone https://github.com/victor-akande/weistack.git
cd weistack
make build
./bin/weistack version
```

## As a service

To run WeiStack as a long-lived service on a Linux machine, for a team or
for other machines on your network, use the hardened systemd unit from the
web-app example: [weistack.service](../examples/web-app/weistack.service).
Step 1 of [that guide](../examples/web-app/README.md) installs it, and
[Other machines](lan.md) explains `-lan`.

## In GitHub Actions

The repository is also a GitHub Action that downloads, verifies and starts
WeiStack for the rest of a job: see [In GitHub Actions](github-action.md).
