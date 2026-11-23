# Step 4: the web app's stack, applied by the deployer.
#
#   internet ── EIP ── ELB (HTTP :80) ──┬── web-1 (zone 1) ── data disk
#                                       └── web-2 (zone 2) ── data disk
#   web subnet  10.0.1.0/24  servers and the load balancer
#   db subnet   10.0.2.0/24  RDS MySQL, reachable from the web tier only
#   NAT gateway with its own EIP: outbound traffic for both subnets
#   OBS bucket: static assets and backups
#   One KMS key encrypts the disks, the database and the bucket.

terraform {
  required_version = ">= 1.6"
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = "1.100.0"
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
  zones = data.huaweicloud_availability_zones.zones.names
  tags  = { app = var.name, env = var.environment }
}

# ---- encryption ------------------------------------------------------------

resource "huaweicloud_kms_key" "app" {
  key_alias         = "${var.name}-${var.environment}"
  key_description   = "Encrypts the ${var.name} disks, database and bucket"
  pending_days      = "7"
  rotation_enabled  = true
  rotation_interval = 365
  tags              = local.tags
}

# ---- network ---------------------------------------------------------------

resource "huaweicloud_vpc" "main" {
  name = "${var.name}-${var.environment}"
  cidr = "10.0.0.0/16"
}

resource "huaweicloud_vpc_subnet" "web" {
  name       = "${var.name}-web"
  cidr       = "10.0.1.0/24"
  gateway_ip = "10.0.1.1"
  vpc_id     = huaweicloud_vpc.main.id
}

resource "huaweicloud_vpc_subnet" "db" {
  name       = "${var.name}-db"
  cidr       = "10.0.2.0/24"
  gateway_ip = "10.0.2.1"
  vpc_id     = huaweicloud_vpc.main.id
}

resource "huaweicloud_networking_secgroup" "web" {
  name                 = "${var.name}-web"
  description          = "Web servers: HTTP from the load balancer's subnet"
  delete_default_rules = true
}

resource "huaweicloud_networking_secgroup_rule" "web_http" {
  security_group_id = huaweicloud_networking_secgroup.web.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = huaweicloud_vpc_subnet.web.cidr
}

resource "huaweicloud_networking_secgroup" "db" {
  name                 = "${var.name}-db"
  description          = "Database: MySQL from the web servers only"
  delete_default_rules = true
}

resource "huaweicloud_networking_secgroup_rule" "db_mysql" {
  security_group_id = huaweicloud_networking_secgroup.db.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3306
  port_range_max    = 3306
  remote_group_id   = huaweicloud_networking_secgroup.web.id
}

# Outbound traffic (package updates, external APIs) leaves through NAT.
resource "huaweicloud_vpc_eip" "nat" {
  name = "${var.name}-nat"
  publicip {
    type = "5_bgp"
  }
  bandwidth {
    name        = "${var.name}-nat"
    size        = 10
    share_type  = "PER"
    charge_mode = "bandwidth"
  }
}

resource "huaweicloud_nat_gateway" "main" {
  name        = "${var.name}-nat"
  description = "Outbound traffic for the web and db subnets"
  spec        = "1"
  vpc_id      = huaweicloud_vpc.main.id
  subnet_id   = huaweicloud_vpc_subnet.web.id
  tags        = local.tags
}

resource "huaweicloud_nat_snat_rule" "subnets" {
  for_each       = { web = huaweicloud_vpc_subnet.web.id, db = huaweicloud_vpc_subnet.db.id }
  nat_gateway_id = huaweicloud_nat_gateway.main.id
  subnet_id      = each.value
  floating_ip_id = huaweicloud_vpc_eip.nat.id
  description    = "Outbound for the ${each.key} subnet"
}

# ---- web tier --------------------------------------------------------------

resource "huaweicloud_compute_instance" "web" {
  count                       = var.web_servers
  name                        = format("%s-web-%d", var.name, count.index + 1)
  image_id                    = data.huaweicloud_images_image.ubuntu.id
  flavor_id                   = var.web_flavor
  security_group_ids          = [huaweicloud_networking_secgroup.web.id]
  availability_zone           = local.zones[count.index % length(local.zones)]
  system_disk_type            = "SSD"
  system_disk_size            = 40
  delete_disks_on_termination = true
  tags                        = local.tags

  network {
    uuid = huaweicloud_vpc_subnet.web.id
  }
}

# Each server's data disk is its own EVS volume, so it outlives a rebuild.
resource "huaweicloud_evs_volume" "web_data" {
  count             = var.web_servers
  name              = format("%s-web-%d-data", var.name, count.index + 1)
  volume_type       = "SSD"
  size              = 20
  availability_zone = huaweicloud_compute_instance.web[count.index].availability_zone
  kms_id            = huaweicloud_kms_key.app.id
  tags              = local.tags
}

resource "huaweicloud_compute_volume_attach" "web_data" {
  count       = var.web_servers
  instance_id = huaweicloud_compute_instance.web[count.index].id
  volume_id   = huaweicloud_evs_volume.web_data[count.index].id
}

resource "huaweicloud_vpc_eip" "lb" {
  name = "${var.name}-lb"
  publicip {
    type = "5_bgp"
  }
  bandwidth {
    name        = "${var.name}-lb"
    size        = 20
    share_type  = "PER"
    charge_mode = "traffic"
  }
}

data "huaweicloud_elb_flavors" "l7" {
  type = "L7"
}

resource "huaweicloud_elb_loadbalancer" "main" {
  name              = "${var.name}-${var.environment}"
  description       = "Public entry point of ${var.name}"
  vpc_id            = huaweicloud_vpc.main.id
  ipv4_subnet_id    = huaweicloud_vpc_subnet.web.ipv4_subnet_id
  ipv4_eip_id       = huaweicloud_vpc_eip.lb.id
  l7_flavor_id      = data.huaweicloud_elb_flavors.l7.flavors[0].id
  availability_zone = local.zones
  tags              = local.tags
}

resource "huaweicloud_elb_listener" "http" {
  name            = "${var.name}-http"
  protocol        = "HTTP"
  protocol_port   = 80
  loadbalancer_id = huaweicloud_elb_loadbalancer.main.id
}

resource "huaweicloud_elb_pool" "web" {
  name        = "${var.name}-web"
  protocol    = "HTTP"
  lb_method   = "ROUND_ROBIN"
  listener_id = huaweicloud_elb_listener.http.id
  # A listener's default pool cannot be deleted, nor a listener that has
  # one (ELB.8907, as on Huawei Cloud): the pool is deleted with its
  # members and health monitor, and unbound from the listener.
  cascade_delete = true
}

resource "huaweicloud_elb_monitor" "web" {
  pool_id     = huaweicloud_elb_pool.web.id
  protocol    = "HTTP"
  interval    = 5
  timeout     = 3
  max_retries = 3
  url_path    = "/healthz"
}

resource "huaweicloud_elb_member" "web" {
  count         = var.web_servers
  pool_id       = huaweicloud_elb_pool.web.id
  address       = huaweicloud_compute_instance.web[count.index].access_ip_v4
  protocol_port = 80
  subnet_id     = huaweicloud_vpc_subnet.web.ipv4_subnet_id
  depends_on    = [huaweicloud_elb_monitor.web]
}

# ---- data tier -------------------------------------------------------------

resource "huaweicloud_rds_instance" "db" {
  name              = "${var.name}-${var.environment}"
  flavor            = var.db_flavor
  vpc_id            = huaweicloud_vpc.main.id
  subnet_id         = huaweicloud_vpc_subnet.db.id
  security_group_id = huaweicloud_networking_secgroup.db.id
  availability_zone = [local.zones[0]]

  db {
    type     = "MySQL"
    version  = "8.0"
    password = var.db_password
  }

  volume {
    type               = "CLOUDSSD"
    size               = 40
    disk_encryption_id = huaweicloud_kms_key.app.id
  }
}

# ---- storage ---------------------------------------------------------------

resource "huaweicloud_obs_bucket" "assets" {
  bucket        = var.bucket
  acl           = "private"
  encryption    = true
  sse_algorithm = "kms"
  kms_key_id    = huaweicloud_kms_key.app.id
}
