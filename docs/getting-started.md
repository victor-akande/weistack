# Getting started

This guide takes you from a fresh clone to Huawei's own Terraform provider
creating resources in WeiStack, in about ten minutes. Each step can be pasted
as it is.

You need Git, Go 1.26 or later, and Make. Step 4 also uses Terraform, and
the snippets use `curl` and `python3`.

## 1. Build

```bash
git clone https://github.com/victor-akande/weistack.git
cd weistack
make build
./bin/weistack version
```

`make` on its own lists every target. The binary in `bin/` has no
dependencies: copy it anywhere.

## 2. Start it

```bash
./bin/weistack
```

At a terminal, WeiStack prints readable logs and a short banner:

```
  WeiStack v0.1.0 is ready on http://127.0.0.1:8780

    Project ID   342f3054dce5eea9034ea3a9858b7f83  (new on every start; -persist keeps it)
    As a proxy   export HTTPS_PROXY=http://127.0.0.1:8780
    Trust its CA curl -o weistack-ca.pem http://127.0.0.1:8780/_weistack/ca
    ...
```

Every request a client makes names a **project ID**. Without `-persist`, a
new one is generated at every start, so fetch it again after a restart (see
[step 5](#5-keep-state-across-restarts)).

Leave WeiStack running and open a second terminal.

## 3. Create something with curl

Every service is reachable under a path prefix, with no DNS or certificate
set-up:

```bash
PROJECT=$(curl -s http://localhost:8780/_weistack/services | python3 -c 'import json,sys; print(json.load(sys.stdin)["project_id"])')
curl -s -X POST http://localhost:8780/vpc/v1/$PROJECT/vpcs -d '{"vpc": {"name": "my-first-vpc", "cidr": "192.168.0.0/16"}}'
```

The new VPC is `CREATING`. A couple of seconds later it is `OK`, as in the
cloud:

```bash
curl -s http://localhost:8780/vpc/v1/$PROJECT/vpcs
```

WeiStack accepts any credentials and unsigned requests. The paths are those
of the real APIs: see the coverage page of each service in
[docs/services](services).

## 4. Use Huawei's Terraform provider

Real tools keep Huawei Cloud's real endpoints and reach WeiStack as an HTTPS
proxy. Nothing is configured per service, and a service WeiStack does not
emulate fails instead of reaching the real cloud.

```bash
mkdir -p ~/weistack-tf && cd ~/weistack-tf
cat > main.tf <<'EOF'
terraform {
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = "1.100.0"
    }
  }
}

variable "project_id" { type = string }

provider "huaweicloud" {
  region     = "ap-southeast-1"
  access_key = "any-access-key"
  secret_key = "any-secret-key"
  project_id = var.project_id
  # After v0.1.1 the provider finds the account through WeiStack's IAM, so
  # no domain_id is needed. With v0.1.x, add any 32 hex characters:
  # domain_id = "fedcba9876543210fedcba9876543210"

  skip_check_website_type = true
  skip_check_upgrade      = true
  max_retries             = 0
}

resource "huaweicloud_vpc" "app" {
  name = "app-vpc"
  cidr = "10.10.0.0/16"
}

resource "huaweicloud_vpc_subnet" "app" {
  name       = "app-subnet"
  cidr       = "10.10.1.0/24"
  gateway_ip = "10.10.1.1"
  vpc_id     = huaweicloud_vpc.app.id
}

resource "huaweicloud_obs_bucket" "assets" {
  bucket = "my-app-assets"
}
EOF
```

WeiStack answers for `*.myhuaweicloud.com` with certificates from its own
certificate authority. Trust it, and route Terraform through WeiStack:

```bash
curl -s -o ~/weistack-ca.pem http://localhost:8780/_weistack/ca
export SSL_CERT_FILE=~/weistack-ca.pem HTTPS_PROXY=http://127.0.0.1:8780 TF_VAR_project_id=$PROJECT
```

The CA is created once and kept (in `~/.config/weistack/tls`), so the file
stays valid across restarts. Instead of trusting it, you can add
`insecure = true` to the provider block.

```bash
terraform init      # the provider download passes through WeiStack untouched
terraform apply
terraform plan      # "No changes": what WeiStack reports matches what was written
terraform destroy
```

Other clients work the same way: see [connecting clients](clients.md) for
the Go and Python SDKs, the OBS SDKs, the AWS CLI and KooCLI.

## 5. Keep state across restarts

```bash
./bin/weistack -persist
```

State, object data and the project ID now live in
`~/.local/share/weistack` (`-data-dir` changes it) and survive a restart.
Work that was in progress when WeiStack stopped, such as a server still
being created, finishes after the next start.

## Tips

- **Faster iteration:** resources take 2 seconds to become ready, as in the
  cloud. `-lifecycle-delay 0` makes every transition instant.
- **Start over:** `curl -X POST http://localhost:8780/_weistack/reset` wipes
  everything.
- **See everything:** `curl http://localhost:8780/_weistack/state` dumps every
  stored resource.
- **Docker:** `docker compose up --build` runs the image with `/data` as a
  volume.
- **All options:** `./bin/weistack -h`, or the table in the
  [README](../README.md#configuration).
