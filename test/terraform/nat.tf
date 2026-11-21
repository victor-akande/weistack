# Public and private NAT gateways, transit subnet and transit IPs, SNAT and
# DNAT rules, and NAT data sources.

resource "huaweicloud_vpc_eip" "nat_snat" {
  name = "tf-nat-snat-eip"

  publicip {
    type = "5_bgp"
  }

  bandwidth {
    name        = "tf-nat-snat-bw"
    size        = 5
    share_type  = "PER"
    charge_mode = "bandwidth"
  }
}

resource "huaweicloud_vpc_eip" "nat_dnat" {
  name = "tf-nat-dnat-eip"

  publicip {
    type = "5_bgp"
  }

  bandwidth {
    name        = "tf-nat-dnat-bw"
    size        = 5
    share_type  = "PER"
    charge_mode = "bandwidth"
  }
}

resource "huaweicloud_nat_gateway" "main" {
  name        = "tf-nat-gw"
  spec        = "1"
  vpc_id      = huaweicloud_vpc.main.id
  subnet_id   = huaweicloud_vpc_subnet.main.id
  description = "tf public nat gateway"

  tags = {
    env = "test"
  }
}

resource "huaweicloud_nat_snat_rule" "main" {
  nat_gateway_id = huaweicloud_nat_gateway.main.id
  subnet_id      = huaweicloud_vpc_subnet.main.id
  floating_ip_id = huaweicloud_vpc_eip.nat_snat.id
  description    = "tf public snat rule"
}

resource "huaweicloud_nat_dnat_rule" "main" {
  nat_gateway_id        = huaweicloud_nat_gateway.main.id
  floating_ip_id        = huaweicloud_vpc_eip.nat_dnat.id
  protocol              = "tcp"
  internal_service_port = 80
  external_service_port = 8080
  port_id               = huaweicloud_compute_instance.web.network[0].port
  description           = "tf public dnat rule"
}

# Private NAT: gateway in the scenario's subnet, transit subnet in a second VPC
# so transit IPs do not belong to the gateway's own VPC.

resource "huaweicloud_vpc" "nat_transit" {
  name = "tf-nat-transit-vpc"
  cidr = "172.16.0.0/16"
}

resource "huaweicloud_vpc_subnet" "nat_transit" {
  name       = "tf-nat-transit-subnet"
  cidr       = "172.16.1.0/24"
  gateway_ip = "172.16.1.1"
  vpc_id     = huaweicloud_vpc.nat_transit.id
}

resource "huaweicloud_nat_private_gateway" "main" {
  name        = "tf-private-nat-gw"
  subnet_id   = huaweicloud_vpc_subnet.main.id
  spec        = "Small"
  description = "tf private nat gateway"

  tags = {
    env = "test"
  }
}

resource "huaweicloud_nat_private_transit_subnet" "main" {
  name                 = "tf-private-transit-subnet"
  description          = "tf private transit subnet"
  virsubnet_id         = huaweicloud_vpc_subnet.nat_transit.id
  virsubnet_project_id = var.project_id

  tags = {
    env = "test"
  }
}

resource "huaweicloud_nat_private_transit_ip" "snat" {
  subnet_id = huaweicloud_nat_private_transit_subnet.main.virsubnet_id

  tags = {
    role = "snat"
  }
}

resource "huaweicloud_nat_private_transit_ip" "dnat" {
  subnet_id = huaweicloud_nat_private_transit_subnet.main.virsubnet_id

  tags = {
    role = "dnat"
  }
}

resource "huaweicloud_nat_private_snat_rule" "main" {
  gateway_id     = huaweicloud_nat_private_gateway.main.id
  transit_ip_ids = [huaweicloud_nat_private_transit_ip.snat.id]
  subnet_id      = huaweicloud_vpc_subnet.main.id
  description    = "tf private snat rule"
}

resource "huaweicloud_nat_private_dnat_rule" "main" {
  gateway_id            = huaweicloud_nat_private_gateway.main.id
  transit_ip_id         = huaweicloud_nat_private_transit_ip.dnat.id
  protocol              = "tcp"
  internal_service_port = 80
  transit_service_port  = 8080
  backend_interface_id  = huaweicloud_compute_instance.web.network[0].port
  description           = "tf private dnat rule"
}

data "huaweicloud_nat_gateways" "main" {
  gateway_id = huaweicloud_nat_gateway.main.id
}

data "huaweicloud_nat_snat_rules" "main" {
  rule_id = huaweicloud_nat_snat_rule.main.id
}

data "huaweicloud_nat_dnat_rules" "main" {
  rule_id = huaweicloud_nat_dnat_rule.main.id
}

data "huaweicloud_nat_private_gateways" "main" {
  gateway_id = huaweicloud_nat_private_gateway.main.id
}

data "huaweicloud_nat_gateway_specs" "all" {}

output "nat" {
  value = {
    public_gw_status         = huaweicloud_nat_gateway.main.status
    public_snat_status       = huaweicloud_nat_snat_rule.main.status
    public_dnat_status       = huaweicloud_nat_dnat_rule.main.status
    private_gw_status        = huaweicloud_nat_private_gateway.main.status
    transit_subnet_status    = huaweicloud_nat_private_transit_subnet.main.status
    transit_ip_snat_status   = huaweicloud_nat_private_transit_ip.snat.status
    transit_ip_dnat_status   = huaweicloud_nat_private_transit_ip.dnat.status
    private_dnat_type        = huaweicloud_nat_private_dnat_rule.main.backend_type
    public_gateways_count    = length(data.huaweicloud_nat_gateways.main.gateways)
    snat_rules_count         = length(data.huaweicloud_nat_snat_rules.main.rules)
    dnat_rules_count         = length(data.huaweicloud_nat_dnat_rules.main.rules)
    private_gateways_count   = length(data.huaweicloud_nat_private_gateways.main.gateways)
    gateway_specs_count      = length(data.huaweicloud_nat_gateway_specs.all.specs)
    private_snat_assoc_count = length(huaweicloud_nat_private_snat_rule.main.transit_ip_associations)
  }
}
