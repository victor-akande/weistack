# Other machines (`-lan`)

WeiStack listens only on this machine by default. To let other machines
on your network use it, such as a laptop running Terraform against a
WeiStack on a home server, start it with `-lan`:

```bash
weistack -lan -persist
```

Other machines then reach it at `https://<this machine>:8781`. WeiStack
on loopback stays as it was, at `http://127.0.0.1:8780`.

## What `-lan` changes

- **A second listener, over HTTPS.** `-lan` opens `-lan-port` (8781 by
  default) on every interface. Its certificate is issued by WeiStack's
  local CA for the name or address the client used, so clients trust the
  CA once (see below) and no certificate warning appears.
- **Credentials are always checked there.** Every request on the `-lan`
  port needs a valid signature or IAM token, and is allowed only what the
  caller's permissions allow, exactly as under
  [`-iam=enforce`](enforce.md), even when WeiStack runs with
  `-iam=accept`. Requests on loopback keep the `-iam` setting.
- **Only nearby clients.** By default the `-lan` port admits loopback,
  private (10/8, 172.16/12, 192.168/16, fc00::/7), shared (100.64/10, as
  VPN meshes use) and link-local addresses, and closes other connections.
  `-lan-clients 192.168.1.0/24,10.0.0.7` admits only those.
- **The admin API needs the administrator.** Over `-lan`, `/_weistack/*`
  answers only the administrator's credentials (`weistack credentials`
  prints them), except `health` and `ca`. Dumping (`/_weistack/state`)
  and wiping (`/_weistack/reset`) the data are only possible from
  WeiStack's own machine.
- **No passing through.** As a proxy, WeiStack answers the emulated
  domains for `-lan` clients, but tunnels to other hosts only for clients
  on its own machine, unless `-proxy-passthrough all` is set.

The log says where `-lan` listens, the addresses other machines can use,
and every refused client; the banner shows the addresses too.

## On the other machine

Fetch the CA once, and use the administrator's keys or an IAM user's:

```bash
curl -k -o weistack-ca.pem https://192.168.1.20:8781/_weistack/ca
# compare it with `weistack ca` on the server before trusting it
export SSL_CERT_FILE=$PWD/weistack-ca.pem
export HW_ACCESS_KEY=... HW_SECRET_KEY=...
```

Then either point the SDK or Terraform at WeiStack as a proxy, keeping
Huawei Cloud's endpoints:

```bash
export HTTPS_PROXY=https://192.168.1.20:8781
```

or address services directly, as on loopback:
`https://192.168.1.20:8781/vpc/v1/{project_id}/vpcs`.

Prefer an IAM user with only the permissions the other machine needs to
the administrator's keys (see [IAM: access keys](services/iam.md#access-keys)).

## Binding beyond loopback

`-host 0.0.0.0` (or any address other than loopback) would serve other
machines over plain HTTP, without the checks above. Outside a container
WeiStack refuses it and points to `-lan`. Inside a container it must bind
every interface to be reached through a published port, so the image
sets `WEISTACK_IN_CONTAINER=1`, which allows it. Publish the port on
loopback unless other machines need it:

```bash
docker run --rm -p 127.0.0.1:8780:8780 victhedev/weistack:latest
```

If you build your own image around the binary, set
`WEISTACK_IN_CONTAINER=1` in it as well.
