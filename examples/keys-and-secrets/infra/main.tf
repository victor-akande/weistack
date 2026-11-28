# Step 4: the stack, applied by the deployer.
#
#   bastion (ECS) ── EIP          SSH in with the KPS key pair
#     ├── system disk (EVS), encrypted with the KMS key
#     └── security group: SSH from the admin network only
#   KMS key: encrypts the key pair's private key, the secret and the disk
#   CSMS secret: the app's API token, read at start, rotated in step 7
#   OBS bucket: the app's configuration, which names the secret but
#   never holds it

terraform {
  required_version = ">= 1.6"
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = "1.100.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
  }
}

provider "huaweicloud" {
  region = var.region
  # The deployer may not read IAM, so the provider is told the project
  # instead of looking it up. Keys come from HW_ACCESS_KEY and HW_SECRET_KEY.
  project_id = var.project_id
}

data "huaweicloud_availability_zones" "zones" {}

data "huaweicloud_images_image" "ubuntu" {
  name        = "Ubuntu 22.04 server 64bit"
  most_recent = true
}

locals {
  tags = { app = var.name, env = var.environment }
}

# ---- encryption --------------------------------------------------------------

# A deleted key waits 7 days before it goes, and keeps its alias until then
# (KMS.1104 "Duplicate key aliases"), so each stack's key gets its own.
resource "random_id" "key" {
  byte_length = 3
}

resource "huaweicloud_kms_key" "app" {
  key_alias       = "${var.name}-${var.environment}-${random_id.key.hex}"
  key_description = "Encrypts the ${var.name} key pair, secret and disk"
  pending_days    = "7"
  tags            = local.tags
}

# ---- the key pair --------------------------------------------------------------

# KPS makes the key pair and keeps its private key, encrypted with the KMS
# key, so it can be exported again later (step 8). Terraform also writes a
# copy for the deployer, readable only by them.
#
# A key pair is the user's own by default (scope "user"): no one else sees
# it, the operator included. The bastion's is the team's, so it is the
# account's. (Terraform calls that scope "account"; the API calls it
# "domain".)
resource "huaweicloud_kps_keypair" "bastion" {
  name            = "${var.name}-bastion"
  scope           = "account"
  description     = "SSH into the ${var.name} bastion"
  encryption_type = "kms"
  kms_key_id      = huaweicloud_kms_key.app.id
  key_file        = "${path.module}/../secrets/bastion.pem"
}

# ---- the secret ----------------------------------------------------------------

resource "random_password" "api_token" {
  length  = 40
  special = false
}

# The app's API token. Step 7 rotates it outside Terraform, as a rotation
# job would, so Terraform sets only the first value and ignores later ones.
resource "huaweicloud_csms_secret" "api_token" {
  name        = "${var.name}-api-token"
  secret_text = random_password.api_token.result
  kms_key_id  = huaweicloud_kms_key.app.id
  description = "The ${var.name} API token"
  tags        = local.tags

  lifecycle {
    ignore_changes = [secret_text]
  }
}

# ---- network -----------------------------------------------------------------

resource "huaweicloud_vpc" "main" {
  name = "${var.name}-${var.environment}"
  cidr = "10.20.0.0/16"
}

resource "huaweicloud_vpc_subnet" "main" {
  name       = "${var.name}-main"
  cidr       = "10.20.1.0/24"
  gateway_ip = "10.20.1.1"
  vpc_id     = huaweicloud_vpc.main.id
}

resource "huaweicloud_networking_secgroup" "bastion" {
  name                 = "${var.name}-bastion"
  description          = "The bastion: SSH from the admin network only"
  delete_default_rules = true
}

resource "huaweicloud_networking_secgroup_rule" "ssh" {
  security_group_id = huaweicloud_networking_secgroup.bastion.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.admin_cidr
}

# ---- the bastion ---------------------------------------------------------------

resource "huaweicloud_compute_instance" "bastion" {
  name                        = "${var.name}-bastion"
  image_id                    = data.huaweicloud_images_image.ubuntu.id
  flavor_id                   = var.flavor
  key_pair                    = huaweicloud_kps_keypair.bastion.name
  security_group_ids          = [huaweicloud_networking_secgroup.bastion.id]
  availability_zone           = data.huaweicloud_availability_zones.zones.names[0]
  system_disk_type            = "SSD"
  system_disk_size            = 40
  system_disk_kms_key_id      = huaweicloud_kms_key.app.id
  delete_disks_on_termination = true
  tags                        = local.tags

  network {
    uuid = huaweicloud_vpc_subnet.main.id
  }
}

resource "huaweicloud_vpc_eip" "bastion" {
  name = "${var.name}-bastion"
  publicip {
    type = "5_bgp"
  }
  bandwidth {
    name        = "${var.name}-bastion"
    size        = 5
    share_type  = "PER"
    charge_mode = "traffic"
  }
}

resource "huaweicloud_vpc_eip_associate" "bastion" {
  public_ip = huaweicloud_vpc_eip.bastion.address
  port_id   = huaweicloud_compute_instance.bastion.network[0].port
}

# ---- configuration ---------------------------------------------------------------

resource "huaweicloud_obs_bucket" "config" {
  bucket        = var.bucket
  acl           = "private"
  encryption    = true
  sse_algorithm = "kms"
  kms_key_id    = huaweicloud_kms_key.app.id
}
