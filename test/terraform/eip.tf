# EIPs, shared bandwidth, bandwidth association, an ECS instance created with
# an EIP, a second EIP associated to the instance's second NIC port, and the
# EIP/bandwidth data sources.

resource "huaweicloud_vpc_eip" "main" {
  name = "tf-eip-main"

  publicip {
    type = "5_bgp"
  }

  bandwidth {
    name        = "tf-eip-main-bw"
    size        = 5
    share_type  = "PER"
    charge_mode = "bandwidth"
  }

  tags = {
    env = "test"
  }

  lifecycle {
    ignore_changes = [bandwidth]
  }
}

resource "huaweicloud_vpc_bandwidth" "shared" {
  name        = "tf-shared-bw"
  size        = 5
  charge_mode = "bandwidth"
}

resource "huaweicloud_vpc_bandwidth_associate" "main" {
  bandwidth_id          = huaweicloud_vpc_bandwidth.shared.id
  eip_id                = huaweicloud_vpc_eip.main.id
  bandwidth_charge_mode = "bandwidth"
  bandwidth_size        = 5
}

resource "huaweicloud_vpc_subnet" "eip_extra" {
  name       = "tf-eip-extra-subnet"
  cidr       = "192.168.2.0/24"
  gateway_ip = "192.168.2.1"
  vpc_id     = huaweicloud_vpc.main.id
}

resource "huaweicloud_compute_instance" "edge" {
  name                      = "tf-edge"
  image_id                  = data.huaweicloud_images_image.ubuntu.id
  flavor_id                 = "s6.small.1"
  security_group_ids        = [huaweicloud_networking_secgroup.web.id]
  availability_zone         = data.huaweicloud_availability_zones.zones.names[0]
  system_disk_type          = "SSD"
  system_disk_size          = 40
  eip_type                  = "5_bgp"
  delete_eip_on_termination = true

  bandwidth {
    share_type  = "PER"
    size        = 5
    charge_mode = "bandwidth"
  }

  network {
    uuid = huaweicloud_vpc_subnet.main.id
  }

  network {
    uuid = huaweicloud_vpc_subnet.eip_extra.id
  }
}

resource "huaweicloud_vpc_eip" "attached" {
  name = "tf-eip-attached"

  publicip {
    type = "5_bgp"
  }

  bandwidth {
    name        = "tf-eip-attached-bw"
    size        = 5
    share_type  = "PER"
    charge_mode = "bandwidth"
  }
}

resource "huaweicloud_vpc_eip_associate" "edge" {
  public_ip = huaweicloud_vpc_eip.attached.address
  port_id   = huaweicloud_compute_instance.edge.network[1].port
}

data "huaweicloud_vpc_eip" "attached" {
  public_ip = huaweicloud_vpc_eip_associate.edge.public_ip
}

data "huaweicloud_vpc_eips" "all" {
  public_ips = [
    huaweicloud_vpc_bandwidth_associate.main.public_ip,
    huaweicloud_vpc_eip_associate.edge.public_ip,
  ]
}

data "huaweicloud_vpc_bandwidth" "shared" {
  name = huaweicloud_vpc_bandwidth_associate.main.bandwidth_name
}

output "eip" {
  value = {
    attached_port_match = data.huaweicloud_vpc_eip.attached.port_id == huaweicloud_compute_instance.edge.network[1].port
    eips_count          = length(data.huaweicloud_vpc_eips.all.eips)
    shared_bw_type      = data.huaweicloud_vpc_bandwidth.shared.share_type
    shared_bw_size      = data.huaweicloud_vpc_bandwidth.shared.size
    shared_bw_eips      = length(data.huaweicloud_vpc_bandwidth.shared.publicips)
    edge_status         = huaweicloud_compute_instance.edge.status
    edge_has_public_ip  = huaweicloud_compute_instance.edge.public_ip != ""
  }
}
