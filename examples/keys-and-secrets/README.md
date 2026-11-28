# Example: SSH keys and secrets, operated and audited

This guide gives a small stack a key pair and a secret the way a team runs
them on Huawei Cloud. Key Pair Service (KPS) keeps the bastion's SSH key,
and Cloud Secret Management Service (CSMS) keeps the application's API
token. The app reads the token at start, the deployer rotates it, the
operator checks everything without being able to read it, and the
administrator audits the whole account from WeiStack's inventory.

It needs WeiStack v0.4.1 or later, and uses every way of reaching it:

| Tool | Who uses it | What for |
| --- | --- | --- |
| **Terraform** | the administrator; the deployer | IAM; the stack, its key pair and its secret |
| **AWS CLI** (S3-compatible) | the deployer | uploading the app's configuration, encrypted |
| **Python SDK** (CSMS) | the app; the deployer | reading the token; rotating it |
| **Go SDK** | the operator; the administrator | checking the stack; reading the inventory |
| **KooCLI** (`hcloud`) | the operator; the deployer | listing key pairs and secrets; recovering a private key |
| **curl** with an IAM token | the operator | following one request through WeiStack's log |
| **GitHub Action** | CI | testing every change to the stack |
| **`weistack` itself** | the cloud's administrator | the inventory, as JSON, with exit codes a script can trust |

WeiStack emulates Huawei Cloud's APIs, so every resource below is created,
checked and reported as Huawei Cloud would, with permissions checked on
every request. No virtual machine boots, so this is the stack's control
plane, the part Terraform, SDKs and CI talk to.

## What you build

```text
 ┌─ VPC 10.20.0.0/16 ───────────────────────────────┐
 │  subnet 10.20.1.0/24                             │
 │    bastion (ECS) ── EIP                          │
 │      key pair: keys-bastion (KPS)                │
 │      system disk (EVS), encrypted                │
 │      security group: SSH from 10.0.0.0/8 only    │
 └──────────────────────────────────────────────────┘
   KMS key: encrypts the key pair's private key, the secret and the disk
   CSMS secret keys-api-token: the app's API token, in versions
   OBS bucket: the app's configuration, which names the secret
```

Three IAM users, each allowed only what its job needs:

| User | Group | May |
| --- | --- | --- |
| `keys-deployer` | `keys-deployers` | build and change the stack, the key pair and the secret; nothing in IAM |
| `keys-operator` | `keys-operators` | see everything, change nothing, and not read secret values |
| `keys-app` | `keys-apps` | read secret values, and nothing else |

## Two machines

This guide uses the same two machines as the
[web-app example](../web-app/README.md#two-machines): a **cloud machine**
that runs WeiStack as a service, and a **workstation** where people run
the tools. One machine can play both roles.

```bash
export CLOUD=192.168.1.20      # your cloud machine's address
```

## 1. The cloud machine: WeiStack as a service

Follow the web-app guide's
[step 1](../web-app/README.md#1-the-cloud-machine-weistack-as-a-service),
with this release:

```bash
VERSION=0.4.1
cd /tmp
curl -fsSLO "https://github.com/victor-akande/weistack/releases/download/v$VERSION/weistack_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/victor-akande/weistack/releases/download/v$VERSION/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "weistack_${VERSION}_linux_amd64.tar.gz" --repo victor-akande/weistack
```

`gh attestation` needs GitHub CLI 2.49 or later; Ubuntu 24.04's package is
older, so install `gh` from its releases.

**Upgrading a running service** keeps its data, keys and CA. Back up first,
with the new binary, while the service is stopped:

```bash
tar -xzf "weistack_${VERSION}_linux_amd64.tar.gz" weistack
sudo systemctl stop weistack
sudo -u weistack ./weistack backup /var/lib/weistack/backups/before-v$VERSION.tar.gz -data-dir /var/lib/weistack/data
sudo install -m 0755 weistack /usr/local/bin/weistack
sudo systemctl start weistack
```

The archive's name comes before the flags. A backup holds the vault key,
so keep it where only the `weistack` user can read it, as here.

The administrator's keys are in the service's TLS directory. Name it,
or `weistack credentials` reads (and creates) keys in your own:

```bash
sudo -u weistack weistack credentials -tls-dir /var/lib/weistack/tls
```

## 2. The workstation: tools and trust

Follow the web-app guide's
[step 2](../web-app/README.md#2-the-workstation-tools-and-trust) to trust
WeiStack's CA and install Terraform, Go and KooCLI (`/etc/hosts` is not
needed here). Then get this example and its Python tools:

```bash
git clone https://github.com/victor-akande/weistack.git ~/weistack
cd ~/weistack/examples/keys-and-secrets
python3 -m venv ~/venv
~/venv/bin/pip install -r requirements.txt
. ~/venv/bin/activate
(cd check && go build -o ../bin/check .)
```

[`use.sh`](use.sh) sets what a tool needs to act as one of the roles, as
in the web-app guide: the role's keys, the region, `HTTPS_PROXY` set to
WeiStack's `-lan` port (the tools keep Huawei Cloud's real endpoints), and
the system's CA bundle.

```bash
export WEISTACK="https://$CLOUD:8781"
. ./use.sh deployer        # or: operator, app
```

Every command from here on runs on the workstation, in
`~/weistack/examples/keys-and-secrets`, unless it says otherwise.

## 3. The administrator sets up IAM

With the administrator's keys from step 1:

```bash
export HW_ACCESS_KEY=... HW_SECRET_KEY=...      # the administrator's
install -d -m 700 secrets
(umask 077; echo "Ops-1$(openssl rand -hex 8)" > secrets/operator-password)
env -u HTTPS_PROXY terraform -chdir=iam init
HTTPS_PROXY=$WEISTACK TF_VAR_operator_password="$(cat secrets/operator-password)" \
  terraform -chdir=iam apply
```

[`iam/main.tf`](iam/main.tf) grants each group Huawei Cloud's own system
policies. KPS and CSMS are part of DEW and have their own:
`DEW KeypairFullAccess` and `CSMS FullAccess` for the deployers, and
`Tenant Guest` for the operators.

The app gets a custom policy of three actions:

```json
{"Version": "1.1", "Statement": [{"Effect": "Allow",
  "Action": ["csms:secret:get", "csms:secretVersion:get", "kms:dek:decrypt"]}]}
```

Reading a secret's value takes two permissions: CSMS's, to read the
version, and KMS's, to decrypt the data key that encrypts it. Tenant Guest
has the first but not the second, so operators can see that the secret
exists, but not what it holds.

Each user's access key is written to `secrets/<role>.csv`.

## 4. The deployer builds the stack

```bash
. ./use.sh deployer
export TF_VAR_project_id="$(terraform -chdir=iam output -raw project_id)"
direct terraform -chdir=infra init
terraform -chdir=infra apply
chmod 600 secrets/bastion.pem
```

[`infra/main.tf`](infra/main.tf) creates the KMS key first, then:

- **The key pair**, `huaweicloud_kps_keypair` with `encryption_type =
  "kms"`. KPS generates it and keeps the private key, encrypted with the
  KMS key, so it can be recovered later (step 10). Terraform writes a copy
  to `secrets/bastion.pem`.
- **Its scope.** A key pair is its creator's by default, and no one else
  sees it, the operator included. The bastion's is the team's, so its
  scope is `account` (the API calls it `domain`).
- **The secret**, `huaweicloud_csms_secret`, from a random 40-character
  token, encrypted with the KMS key. Terraform keeps only a hash of the
  value in its state. `ignore_changes = [secret_text]` leaves later
  versions to the rotation (step 7).
- **The bastion**, created with `key_pair`. WeiStack, like Huawei Cloud,
  refuses a server whose key pair does not exist (`Ecs.0314`).

Check that the saved key is the key pair's:

```bash
ssh-keygen -l -E md5 -f secrets/bastion.pem
terraform -chdir=infra output -raw keypair_fingerprint
```

## 5. The deployer uploads the app's configuration

The configuration names the secret. It never holds the token:

```bash
jq -n --arg s "$(terraform -chdir=infra output -raw secret_name)" '{region: "ap-southeast-1", api_token_secret: $s}' > secrets/config.json
aws configure set default.s3.addressing_style path
aws --endpoint-url "$WEISTACK/obs" s3 cp secrets/config.json "s3://$(terraform -chdir=infra output -raw bucket)/config.json" \
  --sse aws:kms --sse-kms-key-id "$(terraform -chdir=infra output -raw kms_key_id)"
```

## 6. The app reads its token

[`app/api_token.py`](app/api_token.py) is what an app does at start: it
reads the secret's current version with Huawei's Python SDK.

```bash
. ./use.sh app
python app/api_token.py read
```

```text
keys-api-token: version v1 (SYSCURRENT), token sha256 d818836391d7…
```

It prints a fingerprint of the token, never the token: an app should not
log its secrets either.

## 7. The deployer rotates the token

```bash
. ./use.sh deployer
python app/api_token.py rotate
. ./use.sh app
python app/api_token.py read
```

```text
keys-api-token: rotated v1 -> v2; SYSPREVIOUS is v1
keys-api-token: version v2 (SYSCURRENT), token sha256 683d7223af32…
```

A new version becomes `SYSCURRENT`. The one before stays readable as
`SYSPREVIOUS`, so instances that still hold it keep working until they
restart. `terraform -chdir=infra plan` still finds no changes.

## 8. The operator checks the stack

### With the Go SDK

[`check/`](check/main.go) uses Huawei's Go SDK with read-only credentials:

```bash
. ./use.sh operator
./bin/check -project "$TF_VAR_project_id" -server "$(terraform -chdir=infra output -raw server_id)" \
  -keypair keys-bastion -key-file secrets/bastion.pem -secret keys-api-token
```

```text
ok   bastion uses the key pair        key_name "keys-bastion"
ok   saved private key
ok   KPS fingerprint matches          fe:96:18:1a:08:15:f7:cd:e4:2f:6e:00:a3:fd:eb:c4
ok   KPS keeps the private key        is_key_protection true
ok   secret listed
ok   secret value refused             403 CSMS.0302
the stack is as expected
```

### With KooCLI

```bash
hcloud configure set --cli-profile=keys-operator --cli-mode=AKSK --cli-region=ap-southeast-1 \
  --cli-access-key="$HW_ACCESS_KEY" --cli-secret-key="$HW_SECRET_KEY" --cli-project-id="$TF_VAR_project_id"
hcloud KPS ListKeypairs --cli-profile=keys-operator
hcloud CSMS ListSecrets --cli-profile=keys-operator
hcloud CSMS ShowSecretVersion --cli-profile=keys-operator --secret_name=keys-api-token --version_id=latest
```

The last one is refused with `CSMS.0302` and an
`encoded_authorization_message`. KooCLI exits 0 even when the API returns
an error, so a script must read what it prints, as [`test.sh`](test.sh)
does.

### With curl, following one request

Sign in with the operator's password, then send a request with a W3C
`traceparent` header, as a traced client or an agent would:

```bash
TOKEN=$(curl -sS -D - -o /dev/null https://iam.ap-southeast-1.myhuaweicloud.com/v3/auth/tokens \
  -H 'Content-Type: application/json' -d '{"auth": {"identity": {"methods": ["password"], "password": {"user": {
    "name": "keys-operator", "password": "'"$(cat secrets/operator-password)"'", "domain": {"name": "weistack"}}}},
    "scope": {"project": {"id": "'"$TF_VAR_project_id"'"}}}}' | tr -d '\r' | sed -n 's/^X-Subject-Token: //Ip')
trace=$(openssl rand -hex 16)
curl -sS -D - -o /dev/null "https://kms.ap-southeast-1.myhuaweicloud.com/v1/$TF_VAR_project_id/secrets" \
  -H "X-Auth-Token: $TOKEN" -H "traceparent: 00-$trace-$(openssl rand -hex 8)-01" | grep -i traceresponse
echo "$trace"
```

WeiStack joins the trace: `traceresponse` carries the same trace ID, and
step 11 finds the request in WeiStack's log by it.

A mistake gets a hint, in a header, so the body stays exactly Huawei
Cloud's:

```bash
curl -sS -D - -o /dev/null "https://kms.ap-southeast-1.myhuaweicloud.com/v1/$TF_VAR_project_id/secrets" \
  -H "X-Auth-Token: not-a-token" | grep -i x-weistack-hint
```

```text
X-WeiStack-Hint: the X-Auth-Token is not one this WeiStack issued: get a token from POST /v3/auth/tokens
```

## 9. The administrator audits the account

[`GET /_weistack/inventory`](../../docs/inventory.md) lists every
resource in the account, with its tags and relationships, in the shapes
of Huawei Cloud's Config service. Under `-iam=enforce` only the
administrator may read it, signed like any API call. The Go check signs it
with the SDK's signer:

```bash
HW_ACCESS_KEY=... HW_SECRET_KEY=... ./bin/check -inventory \
  -server "$(terraform -chdir=infra output -raw server_id)" \
  -ids "vpc.vpcs=$(terraform -chdir=infra output -raw vpc_id),kps.keypairs=keys-bastion"
```

```text
ok   listed vpc.vpcs                  a7aab475-0e66-4128-bc09-c99371b09a46
ok   listed kps.keypairs              keys-bastion
ok   bastion isContainedIn vpc.vpcs   a7aab475-0e66-4128-bc09-c99371b09a46
     26 resources in the inventory
```

[`test.sh`](test.sh) checks the bastion's four relationships, as Config
reports them: it `isContainedIn` the VPC, `isAttachedTo` its EIP and its
disk, and `isAssociatedWith` its security group.

## 10. The deployer recovers the private key

Lost `secrets/bastion.pem`? KPS kept it:

```bash
. ./use.sh deployer
hcloud configure set --cli-profile=keys-deployer --cli-mode=AKSK --cli-region=ap-southeast-1 \
  --cli-access-key="$HW_ACCESS_KEY" --cli-secret-key="$HW_SECRET_KEY" --cli-project-id="$TF_VAR_project_id"
(umask 077; hcloud KPS ExportPrivateKey --cli-profile=keys-deployer --keypair.name=keys-bastion \
  | jq -r .keypair.private_key > secrets/recovered.pem)
ssh-keygen -l -E md5 -f secrets/recovered.pem
```

Exporting needs `kps:SSHKeyPair:exportPrivateKey`, which
`DEW KeypairReadOnlyAccess` does not grant, and KMS's permission to
decrypt.

## 11. On the cloud machine: the log and the inventory, as JSON

Find step 8's request by its trace ID:

```bash
journalctl -u weistack -o cat | grep '"trace_id":"<the trace ID>"' | jq -c '{method, host, path, status, operation}'
```

```json
{"method":"GET","host":"kms.ap-southeast-1.myhuaweicloud.com","path":"/v1/.../secrets","status":200,"operation":"ListSecrets"}
```

`weistack admin` signs calls to the admin API as the administrator, and
`-output json` makes its output and its failures machine-readable. The
method and path come before the flags:

```bash
A="-tls-dir /var/lib/weistack/tls -output json"
sudo -u weistack weistack admin GET 'inventory?type=kps.keypairs' $A | jq '.resources[] | {name, created}'
sudo -u weistack weistack admin GET 'inventory?type=kps.nope' $A; echo "exit $?"
```

```text
{"error":{"kind":"api","exit_code":4,...,"hint":"give a type as provider.type, such as ecs.cloudservers; docs/inventory.md lists them"}}
exit 4
```

A script can tell failures apart by exit code: 2 a usage error, 3 WeiStack
unreachable, 4 the API refused, 5 a data or credentials problem.

## 12. Tear down

```bash
. ./use.sh deployer
aws --endpoint-url "$WEISTACK/obs" s3 rm "s3://$(terraform -chdir=infra output -raw bucket)/" --recursive
terraform -chdir=infra destroy
HW_ACCESS_KEY=... HW_SECRET_KEY=... HTTPS_PROXY=$WEISTACK \
  TF_VAR_operator_password="$(cat secrets/operator-password)" terraform -chdir=iam destroy
rm -rf secrets
```

Empty the bucket first: OBS refuses to delete a bucket that holds objects.
The KMS key waits 7 days before it is deleted, as on Huawei Cloud, so each
stack's key alias gets a random suffix.

## Test every change in CI

[`ci/keys-and-secrets.yml`](ci/keys-and-secrets.yml) runs this guide on
every pull request: WeiStack starts inside the job with `-iam=enforce
-lan`, and [`test.sh`](test.sh) runs steps 3 to 10 and 12. Copy it to
`.github/workflows/` in the repository that holds these files.

To run it on the workstation instead:

```bash
WEISTACK=https://$CLOUD:8781 ADMIN_AK=... ADMIN_SK=... ./test.sh
```

## When something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `KPS.6004` for a key pair that exists | its scope is `user`: only its creator sees it | create it with `scope = "account"` |
| a second plan replaces the key pair | `scope = "domain"` in Terraform | Terraform's name for it is `account` |
| `Ecs.0314` creating the server | the key pair does not exist in that project | create it first; reference `huaweicloud_kps_keypair.<name>.name` |
| `CSMS.0302` reading a value | the caller lacks `csms:secretVersion:get` or `kms:dek:decrypt` | grant both, as the app's policy does |
| `DEW KeypairFullAccess` not found | WeiStack is older than v0.4.1 | upgrade (step 1) |
| `Authentication failed` in step 3 | the administrator's keys came from another TLS directory | `weistack credentials -tls-dir /var/lib/weistack/tls` |
| `BucketAlreadyOwnedByYou` on a second run | an earlier teardown stopped at a bucket that still held objects | empty it and run `terraform destroy` again |
| a script thinks a KooCLI call worked | KooCLI exits 0 on API errors | check its output for `error_code` |

## Not in this stack yet

- **SSH to the bastion.** No virtual machine boots, so the key pair is
  checked by fingerprint, not by logging in.
- **Rotating with a function.** CSMS's automatic rotation (`RotateSecret`)
  calls FunctionGraph, which WeiStack does not emulate. Rotate from a job,
  as step 7 does.
