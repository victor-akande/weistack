# The end-to-end scenario run by run.sh: a small web stack applied,
# planned again and destroyed through WeiStack's HTTPS proxy. The
# provider keeps Huawei Cloud's real endpoints; nothing here points at
# WeiStack except HTTPS_PROXY, set by run.sh.

terraform {
  required_version = ">= 1.6"
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = "1.100.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "The emulator's project ID (GET /_weistack/services)."
}

provider "huaweicloud" {
  region     = "ap-southeast-1"
  access_key = "AKWEISTACKTERRAFORM"
  secret_key = "weistack-does-not-verify-signatures"
  project_id = var.project_id
  # Any domain ID: it spares the provider an IAM lookup.
  domain_id = "fedcba9876543210fedcba9876543210"

  skip_check_website_type = true
  skip_check_upgrade      = true
  max_retries             = 0

  # WeiStack presents certificates from its own CA. Instead of this,
  # SSL_CERT_FILE can name the output of `weistack ca`.
  insecure = true
}

data "huaweicloud_availability_zones" "zones" {}

data "huaweicloud_images_image" "ubuntu" {
  name        = "Ubuntu 22.04 server 64bit"
  most_recent = true
}

resource "huaweicloud_vpc" "main" {
  name = "tf-vpc"
  cidr = "192.168.0.0/16"
}

resource "huaweicloud_vpc_subnet" "main" {
  name       = "tf-subnet"
  cidr       = "192.168.1.0/24"
  gateway_ip = "192.168.1.1"
  vpc_id     = huaweicloud_vpc.main.id
}

resource "huaweicloud_networking_secgroup" "web" {
  name                 = "tf-web"
  delete_default_rules = true
}

resource "huaweicloud_networking_secgroup_rule" "ssh" {
  security_group_id = huaweicloud_networking_secgroup.web.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
}

resource "huaweicloud_compute_instance" "web" {
  name               = "tf-web"
  image_id           = data.huaweicloud_images_image.ubuntu.id
  flavor_id          = "s6.small.1"
  security_group_ids = [huaweicloud_networking_secgroup.web.id]
  availability_zone  = data.huaweicloud_availability_zones.zones.names[0]
  system_disk_type   = "SSD"
  system_disk_size   = 40

  network {
    uuid = huaweicloud_vpc_subnet.main.id
  }
}

resource "huaweicloud_obs_bucket" "assets" {
  bucket = "tf-assets-bucket"
}

resource "huaweicloud_rds_instance" "db" {
  name              = "tf-mysql"
  flavor            = "rds.mysql.n1.large.2"
  vpc_id            = huaweicloud_vpc.main.id
  subnet_id         = huaweicloud_vpc_subnet.main.id
  security_group_id = huaweicloud_networking_secgroup.web.id
  availability_zone = [data.huaweicloud_availability_zones.zones.names[0]]

  db {
    type     = "MySQL"
    version  = "8.0"
    password = "Weistack!2026"
  }

  volume {
    type = "CLOUDSSD"
    size = 40
  }
}

output "server_status" {
  value = huaweicloud_compute_instance.web.status
}

output "server_ip" {
  value = huaweicloud_compute_instance.web.access_ip_v4
}

output "rds_status" {
  value = huaweicloud_rds_instance.db.status
}

output "bucket_domain" {
  value = huaweicloud_obs_bucket.assets.bucket_domain_name
}
