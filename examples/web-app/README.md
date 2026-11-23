# Example: a production-style web app

This guide deploys a three-tier web application on WeiStack, from an empty
machine to a running stack, then operates it, breaks it, recovers it, tests
it in CI, and tears it down. It uses every way of reaching WeiStack:

| Tool | Who uses it | What for |
| --- | --- | --- |
| **Terraform** | the administrator; the deployer | IAM; the whole stack |
| **curl** with an IAM token | the operator | reading the stack after signing in with a password |
| **KooCLI** (`hcloud`) | the operator | day-to-day checks |
| **Python SDK** and **OBS SDK for Python** | the deployer | the release: reading the database's address, uploading the site |
| **AWS CLI** (S3-compatible) | the deployer | syncing backups to the bucket |
| **Go SDK** | the operator | a smoke check that fails when the stack is unhealthy |
| **GitHub Action** | CI | testing every change to the stack |
| **`weistack` itself** | the cloud's administrator | service, credentials, faults, backup and restore |

WeiStack emulates Huawei Cloud's APIs: every resource below is created,
tracked and reported as Huawei Cloud would, with permissions checked on
every request. No virtual machine boots and no database serves queries,
so this is the stack's control plane, the part Terraform, SDKs and CI
talk to.

## What you build

```text
              internet
                 │
          EIP (load balancer)                 EIP (NAT, outbound)
                 │                                   │
 ┌─ VPC 10.0.0.0/16 ─────────────────────────────────┼──────────┐
 │  web subnet 10.0.1.0/24                           │          │
 │    ELB (HTTP :80, health check /healthz)    NAT gateway      │
 │      ├── web-1 (zone a) + encrypted data disk     │          │
 │      └── web-2 (zone b) + encrypted data disk  SNAT for both │
 │  db subnet 10.0.2.0/24                          subnets      │
 │    RDS MySQL 8.0 (encrypted), port 3306 from the web tier only │
 └──────────────────────────────────────────────────────────────┘
   OBS bucket: the site and backups, encrypted
   KMS key: encrypts the disks, the database and the bucket
```

Three people share the work, each with only the permissions they need:

- the **administrator** holds WeiStack's administrator keys and sets up IAM;
- the **deployer** (`web-app-deployer`, a key) builds and changes the
  stack, and can do nothing in IAM;
- the **operator** (`web-app-operator`, a password and a key) can look at
  everything and change nothing.

## Two machines

| Machine | Role | Tested on |
| --- | --- | --- |
| the **cloud machine** | runs WeiStack as a service, as a cloud region would be | Ubuntu 24.04, a KVM virtual machine |
| the **workstation** | where people run Terraform, the CLIs and the scripts | Ubuntu 24.04, an LXC container |

They reach each other over a private network. The workstation talks to
WeiStack over HTTPS with [`-lan`](../../docs/lan.md), with credentials
checked on every request. One machine can play both roles: use its own
address as the cloud machine's.

In the commands, `$CLOUD` is the cloud machine's address. Set it in every
shell on the workstation:

```bash
export CLOUD=10.1.1.64
```

The steps take about 30 minutes, most of it installing tools.

## 1. The cloud machine: WeiStack as a service

Download the release, check it, and install it:

```bash
cd /tmp
curl -fsSLO https://github.com/victor-akande/weistack/releases/download/v0.3.0/weistack_0.3.0_linux_amd64.tar.gz
curl -fsSLO https://github.com/victor-akande/weistack/releases/download/v0.3.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf weistack_0.3.0_linux_amd64.tar.gz weistack
sudo install -m 0755 weistack /usr/local/bin/weistack
weistack version
```

With the [GitHub CLI](https://cli.github.com/), also check that the
archive was built by the project's release workflow:
`gh attestation verify weistack_0.3.0_linux_amd64.tar.gz --repo victor-akande/weistack`.

Run it as its own user, under systemd, with [`weistack.service`](weistack.service):

```bash
sudo useradd --system --home-dir /var/lib/weistack --no-create-home --shell /usr/sbin/nologin weistack
sudo curl -fsSL -o /etc/systemd/system/weistack.service \
  https://raw.githubusercontent.com/victor-akande/weistack/main/examples/web-app/weistack.service
sudo systemctl daemon-reload
sudo systemctl enable --now weistack
systemctl status weistack --no-pager --lines=3
```

The service runs `weistack -persist -iam=enforce -lan`:

- `-persist` keeps everything in `/var/lib/weistack/data` across restarts;
- `-iam=enforce` checks every request's signature and permissions;
- `-lan` serves other machines over HTTPS on port 8781, and keeps the
  plain-HTTP port 8780 on loopback.

The unit is hardened: WeiStack can write only its state directory.

WeiStack generated its administrator keys and a certificate authority on
first start. Print the keys; the administrator needs them in step 3:

```bash
sudo -u weistack weistack credentials -tls-dir /var/lib/weistack/tls
```

Print the CA's fingerprint, to check the copy the workstation downloads:

```bash
sudo -u weistack weistack ca -tls-dir /var/lib/weistack/tls | openssl x509 -noout -fingerprint -sha256
```

If a firewall runs, open port 8781 to the workstation only, for example
`sudo ufw allow from 10.1.1.0/24 to any port 8781 proto tcp`.

## 2. The workstation: tools and trust

### Trust WeiStack's CA

Download the CA and compare its fingerprint with the one the cloud machine
printed. Only then trust it:

```bash
curl -fsSk -o ~/weistack-ca.pem "https://$CLOUD:8781/_weistack/ca"
openssl x509 -noout -fingerprint -sha256 -in ~/weistack-ca.pem
sudo cp ~/weistack-ca.pem /usr/local/share/ca-certificates/weistack.crt
sudo update-ca-certificates
curl -fsS "https://$CLOUD:8781/_weistack/health"
```

The last command verifies WeiStack's certificate with the system's CAs.
Since v0.3 a WeiStack CA can sign only the names WeiStack answers (Huawei
Cloud's domains, private addresses, `.local`, `.lan`, `.internal`,
`.home.arpa`), so trusting it does not let it impersonate other sites.

### Install the tools

```bash
sudo apt-get update
sudo apt-get install -y curl jq unzip gnupg git python3-venv ca-certificates

# Terraform, from HashiCorp's repository
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(. /etc/os-release; echo "$VERSION_CODENAME") main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y terraform

# Go, for the smoke check
curl -fsSL "https://go.dev/dl/$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1).linux-amd64.tar.gz" -o /tmp/go.tgz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go

# KooCLI, Huawei's installer; it leaves hcloud readable by root only
curl -fsSL -o /tmp/hcloud_install.sh https://ap-southeast-3-hwcloudcli.obs.ap-southeast-3.myhuaweicloud.com/cli/latest/hcloud_install.sh
sudo bash /tmp/hcloud_install.sh -y
sudo chmod 755 /usr/local/bin/hcloud
```

Get this example and its Python tools (the Python SDK, the OBS SDK and the
AWS CLI, pinned in [`requirements.txt`](requirements.txt)):

```bash
git clone https://github.com/victor-akande/weistack.git ~/weistack
cd ~/weistack/examples/web-app
python3 -m venv ~/venv
~/venv/bin/pip install -r requirements.txt
. ~/venv/bin/activate
```

The OBS SDK for Python cannot use an HTTPS proxy, so it calls OBS's own
name on the `-lan` port. Point that name at the cloud machine:

```bash
echo "$CLOUD obs.ap-southeast-1.myhuaweicloud.com" | sudo tee -a /etc/hosts
```

### How the tools reach WeiStack

[`use.sh`](use.sh) sets everything a tool needs to act as one of the roles:

```bash
export WEISTACK="https://$CLOUD:8781"
. ./use.sh deployer        # or: . ./use.sh operator
```

- **Keys:** the role's, from `secrets/` (step 3), in the variables
  Terraform, the SDKs, KooCLI and the AWS CLI read.
- **Proxy:** `HTTPS_PROXY` is WeiStack's `-lan` port. The tools keep Huawei
  Cloud's real endpoints, `https://vpc.ap-southeast-1.myhuaweicloud.com`
  and so on, and WeiStack answers them. Nothing in Terraform or the scripts
  names WeiStack.
- **Exceptions:** over `-lan`, WeiStack answers only what it emulates.
  KooCLI's metadata downloads, and requests addressed to the cloud machine
  itself (the AWS CLI's), go direct (`NO_PROXY`).
- **Certificates:** Python and the AWS CLI are pointed at the system's CA
  bundle, which now holds WeiStack's CA.

Every command from here on runs on the workstation, in
`~/weistack/examples/web-app`, unless it says otherwise.

## 3. The administrator sets up IAM

The administrator uses WeiStack's administrator keys once, to create the
two groups and two users with [`iam/main.tf`](iam/main.tf). Paste the
keys `weistack credentials` printed in step 1:

```bash
export HW_ACCESS_KEY=... HW_SECRET_KEY=...
export HTTPS_PROXY="https://$CLOUD:8781"

install -d -m 700 secrets
(umask 077; echo "Ops-1$(openssl rand -hex 8)" > secrets/operator-password)

HTTPS_PROXY= terraform -chdir=iam init
TF_VAR_operator_password="$(cat secrets/operator-password)" terraform -chdir=iam apply
unset HW_ACCESS_KEY HW_SECRET_KEY HTTPS_PROXY
```

`terraform init` runs without the proxy: it downloads the provider from
the public registry.

What it creates:

| Group | Permissions | Scope |
| --- | --- | --- |
| `web-app-deployers` | `VPC FullAccess`, `ECS FullAccess`, `EVS FullAccess`, `IMS ReadOnlyAccess`, `ELB FullAccess`, `NAT FullAccess`, `RDS FullAccess`, `KMS Administrator` | the region's project |
| | `OBS Administrator` | the account (OBS is a global service) |
| `web-app-operators` | `Tenant Guest` (read-only, every service) | all projects |

The deployer's and the operator's access keys are saved to
`secrets/deployer.csv` and `secrets/operator.csv`, readable only by you.
`.gitignore` keeps `secrets/` and Terraform's state out of Git.

The administrator's keys are not used again until step 10. In a team, the
administrator runs this step from their own machine.

## 4. The deployer builds the stack

```bash
. ./use.sh deployer
(umask 077; echo "Db-1$(openssl rand -hex 8)" > secrets/db-password)
export TF_VAR_project_id="$(terraform -chdir=iam output -raw project_id)"
export TF_VAR_db_password="$(cat secrets/db-password)"

HTTPS_PROXY= terraform -chdir=infra init
terraform -chdir=infra apply
```

[`infra/`](infra/) creates 27 resources in about a minute. Terraform waits
for each to become ready, as against Huawei Cloud: the servers `ACTIVE`,
the database `ACTIVE`, the volumes attached. Then:

```bash
terraform -chdir=infra output
terraform -chdir=infra plan -detailed-exitcode   # 0: no changes
```

A second plan finds nothing to change: everything WeiStack reports back
matches what was written.

The provider is given the project ID (`TF_VAR_project_id`). Without it,
it would look the project up through IAM, which the deployer may not do:
`IAM.0003 Policy doesn't allow iam:projects:list to be performed`, as
Huawei Cloud answers.

## 5. The operator looks around

### With curl and an IAM token

The operator signs in with a password, as a person at a terminal would,
and uses the token:

```bash
. ./use.sh operator
P="$(terraform -chdir=iam output -raw project_id)"
TOKEN=$(curl -sS -D - -o /dev/null https://iam.ap-southeast-1.myhuaweicloud.com/v3/auth/tokens \
  -H 'Content-Type: application/json' -d @- <<EOF | tr -d '\r' | sed -n 's/^[Xx]-[Ss]ubject-[Tt]oken: //p'
{"auth": {"identity": {"methods": ["password"], "password": {"user": {
  "name": "web-app-operator", "password": "$(cat secrets/operator-password)", "domain": {"name": "weistack"}}}},
  "scope": {"project": {"id": "$P"}}}}
EOF
)

curl -sS "https://elb.ap-southeast-1.myhuaweicloud.com/v3/$P/elb/pools/$(terraform -chdir=infra output -raw pool_id)/members" \
  -H "X-Auth-Token: $TOKEN" | jq -c '.members[] | {address, operating_status}'
```

```json
{"address":"10.0.1.3","operating_status":"ONLINE"}
{"address":"10.0.1.5","operating_status":"ONLINE"}
```

curl reads `https_proxy` too, so it uses the same endpoints as every other
tool. The operator may read, but not change:

```bash
curl -sS "https://vpc.ap-southeast-1.myhuaweicloud.com/v1/$P/vpcs" -H "X-Auth-Token: $TOKEN" \
  -H 'Content-Type: application/json' -d '{"vpc":{"name":"rogue","cidr":"172.16.0.0/16"}}' | jq .message
```

```json
"Policy doesn't allow vpc:vpcs:create to be performed."
```

### With KooCLI

```bash
hcloud configure set --cli-agree-privacy-statement=true
hcloud configure set --cli-profile=web-app-operator --cli-mode=AKSK --cli-region=ap-southeast-1 \
  --cli-access-key="$HW_ACCESS_KEY" --cli-secret-key="$HW_SECRET_KEY" --cli-project-id="$P"

hcloud ECS ListServersDetails --cli-profile=web-app-operator \
  | jq -c '.servers[] | {name, status, zone: ."OS-EXT-AZ:availability_zone"}'
hcloud RDS ListInstances --cli-profile=web-app-operator | jq -c '.instances[] | {name, status, private_ips}'
hcloud VPC ShowQuota/v2 --cli-profile=web-app-operator --type=vpc | jq -c '.quotas.resources[]'
```

```json
{"name":"web-app-web-2","status":"ACTIVE","zone":"ap-southeast-1b"}
{"name":"web-app-web-1","status":"ACTIVE","zone":"ap-southeast-1a"}
{"name":"web-app-prod","status":"ACTIVE","private_ips":["10.0.2.2"]}
{"type":"vpc","used":1,"quota":150,"min":0}
```

The quota is Huawei Cloud's default for a new account; WeiStack enforces
it ([quotas](../../docs/quotas.md)).

## 6. The deployer releases the site

[`release.py`](release.py) is what a release job runs:

```bash
. ./use.sh deployer
python release.py v1
```

```text
database web-app-prod: ACTIVE at 10.0.2.2:3306
uploaded releases/v1/config.json (KMS-encrypted)
uploaded current/config.json (KMS-encrypted)
uploaded releases/v1/index.html (KMS-encrypted)
uploaded current/index.html (KMS-encrypted)
```

1. **Huawei's Python SDK** reads the database's address from RDS, through
   the proxy.
2. The site's configuration is rendered with it.
3. **The OBS SDK for Python** uploads the site, and checks that OBS
   encrypted every object with the stack's KMS key: the bucket encrypts
   by default (`sse_algorithm = "kms"` in [`infra/main.tf`](infra/main.tf)).

Uploading to an SSE-KMS bucket needs KMS permission as well as OBS's
(`kms:cmk:createDataKey`): the deployer's `KMS Administrator` in the
region's project gives it.

## 7. The deployer syncs backups with the AWS CLI

OBS is S3-compatible, so S3 tools work. The AWS CLI addresses WeiStack's
`/obs` endpoint directly:

```bash
mkdir -p backups && echo "-- web-app database dump" | gzip > "backups/db-$(date -u +%Y%m%d).sql.gz"
BUCKET="$(terraform -chdir=infra output -raw bucket)"
aws configure set default.s3.addressing_style path

aws --endpoint-url "$WEISTACK/obs" s3 sync backups/ "s3://$BUCKET/backups/" \
  --sse aws:kms --sse-kms-key-id "$(terraform -chdir=infra output -raw kms_key_id)"
aws --endpoint-url "$WEISTACK/obs" s3 ls "s3://$BUCKET/" --recursive
```

```text
2026-11-23 16:39:10         82 backups/db-20261123.sql.gz
2026-11-23 16:38:54         66 current/config.json
2026-11-23 16:38:54         57 current/index.html
2026-11-23 16:38:54         66 releases/v1/config.json
2026-11-23 16:38:54         57 releases/v1/index.html
```

## 8. The operator runs the smoke check

[`smoke/`](smoke/main.go) is a Go program, built on Huawei's Go SDK, that
checks the stack with read-only keys and exits non-zero when something is
wrong. Run it after every change, or from monitoring:

```bash
(cd smoke && HTTPS_PROXY= go build -o ../bin/smoke .)
. ./use.sh operator
out() { terraform -chdir=infra output -raw "$1"; }
./bin/smoke -project "$P" -pool "$(out pool_id)" -nat "$(out nat_gateway_id)" -db "$(out db_id)" -servers "$(out web_server_count)"
```

```text
ok   web servers                  2 ACTIVE, want 2
ok   load balancer members        2 ONLINE, want 2
ok   NAT gateway                  ACTIVE
ok   database                     ACTIVE
the stack is healthy
```

The Go SDK does not read `HTTPS_PROXY`: the program sets the proxy from
`WEISTACK`, and verifies WeiStack's certificate with the system's CAs.

## 9. Day 2: scale out, with a failure

Traffic grows and the deployer adds a third web server. To rehearse what
happens when the cloud fails, the cloud's administrator first makes the
next server build fail. **On the cloud machine:**

```bash
sudo -u weistack weistack admin POST faults \
  '{"type": "lifecycle", "transition": "ecs.server.build", "times": 1}' -tls-dir /var/lib/weistack/tls
```

**On the workstation**, scale to three:

```bash
. ./use.sh deployer
export TF_VAR_web_servers=3
terraform -chdir=infra apply
```

```text
Error: Job failed with code Ecs.0000: one or more sub-jobs failed
```

The smoke check sees it:

```bash
. ./use.sh operator
./bin/smoke -project "$P" -pool "$(out pool_id)" -nat "$(out nat_gateway_id)" -db "$(out db_id)" -servers 3
```

```text
FAIL web servers                  2 ACTIVE, want 3
FAIL load balancer members        2 ONLINE, want 3
ok   NAT gateway                  ACTIVE
ok   database                     ACTIVE
2 check(s) failed
```

Terraform marked the failed server tainted. Apply again, and it is
replaced:

```bash
. ./use.sh deployer
terraform -chdir=infra apply      # huaweicloud_compute_instance.web[2] is tainted, so must be replaced
. ./use.sh operator
./bin/smoke -project "$P" -pool "$(out pool_id)" -nat "$(out nat_gateway_id)" -db "$(out db_id)" -servers "$(out web_server_count)"
```

```text
ok   web servers                  3 ACTIVE, want 3
ok   load balancer members        3 ONLINE, want 3
...
the stack is healthy
```

[Faults](../../docs/faults.md) can also throttle a service, delay
requests, or leave a database or NAT gateway failed.

### Back up and restore the cloud itself

The cloud machine's data is WeiStack's: a backup holds every account,
resource, key and object. **On the cloud machine**, back it up while it
runs, then rehearse losing it:

```bash
cd /var/lib/weistack
sudo install -d -o weistack -g weistack -m 700 backups
sudo -u weistack weistack backup "backups/weistack-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" -data-dir data -tls-dir tls

sudo systemctl stop weistack
sudo mv data data.lost
sudo -u weistack weistack restore "$(ls -t backups/*.tar.gz | head -1)" -data-dir data
sudo systemctl start weistack
```

The smoke check on the workstation passes again, then
`sudo rm -rf /var/lib/weistack/data.lost`. Copy the backups off the
machine as you would any other.

## 10. Test every change in CI

[`ci/web-app.yml`](ci/web-app.yml) is a GitHub Actions workflow for the
repository that holds these files. On each pull request it starts
WeiStack inside the job with the [GitHub Action](../../docs/github-action.md):

```yaml
- uses: victor-akande/weistack@v0.3.0
  id: weistack
  with:
    iam: enforce
    args: -lan
    proxy: false
```

It then trusts the action's CA, installs the tools, and runs
[`test.sh`](test.sh), which does steps 3 to 9 and 11 as written here: the
administrator's IAM, the deployer's stack and a second plan, the
operator's token and denial, the release, the backup sync, the smoke
check, scaling out, and the teardown. A typo, a missing permission or a
resource that never becomes healthy fails the pull request, not
production. No cloud account, secret or bill is involved.

`test.sh` runs against the workstation's WeiStack as well:

```bash
WEISTACK="https://$CLOUD:8781" ADMIN_AK=... ADMIN_SK=... ./test.sh
```

## 11. Tear down

The deployer empties the bucket and destroys the stack, then the
administrator removes the users and groups:

```bash
. ./use.sh deployer
aws --endpoint-url "$WEISTACK/obs" s3 rm "s3://$BUCKET/" --recursive
terraform -chdir=infra destroy

export HW_ACCESS_KEY=... HW_SECRET_KEY=...      # the administrator's, from step 1
HTTPS_PROXY="$WEISTACK" TF_VAR_operator_password="$(cat secrets/operator-password)" terraform -chdir=iam destroy
unset HW_ACCESS_KEY HW_SECRET_KEY
rm -rf secrets site backups
```

The KMS key is scheduled for deletion in 7 days, as on Huawei Cloud.

To remove WeiStack from the cloud machine:

```bash
sudo systemctl disable --now weistack
sudo rm /etc/systemd/system/weistack.service /usr/local/bin/weistack
sudo rm -rf /var/lib/weistack
sudo userdel weistack
```

## When something goes wrong

| What you see | Why | Fix |
| --- | --- | --- |
| `IAM.0003 Policy doesn't allow iam:projects:list` from the provider | the deployer may not read IAM | pass the project ID (`TF_VAR_project_id`), as step 4 does |
| `AccessDenied` from OBS on an upload | SSE-KMS needs KMS permission too | grant `KMS Administrator` in the region's project |
| `ELB.8907 ... conflict` destroying a pool | a listener's default pool cannot be deleted | `cascade_delete = true` on the pool, as in `infra/` |
| `[APIE_ERROR]Failed to obtain service list` from KooCLI | over `-lan` WeiStack does not pass KooCLI's metadata downloads through | `. ./use.sh`, which sends them direct |
| `/usr/local/bin/hcloud: Permission denied` | Huawei's installer made it readable by root only | `sudo chmod 755 /usr/local/bin/hcloud` |
| `RemoteDisconnected` from the OBS SDK for Python | it cannot use an HTTPS proxy | the `/etc/hosts` entry of step 2 |
| `SSL certificate problem` | the CA is not in the system's store, or a WeiStack older than v0.3.0 | step 2; the cloud machine's log names refused clients |
| `proxy refused a request` in the cloud machine's log | over `-lan`, WeiStack answers only what it emulates | send that host direct (`NO_PROXY`) |

The cloud machine's log is `journalctl -u weistack`. Every request is
there, and every denial with the action and the reason.

## Not in this stack yet

These are common in production, but WeiStack does not emulate them yet, so
the stack leaves them out:

- tags on the VPC, the subnets, the RDS instance and the bucket;
- an RDS automated-backup policy (`backup_strategy`);
- versioning on the bucket.

Applying them fails with `WeiStack.0501` (or OBS's `NotImplemented`).
