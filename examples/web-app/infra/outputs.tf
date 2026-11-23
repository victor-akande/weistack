output "lb_public_ip" {
  value = huaweicloud_vpc_eip.lb.address
}

output "lb_id" {
  value = huaweicloud_elb_loadbalancer.main.id
}

output "pool_id" {
  value = huaweicloud_elb_pool.web.id
}

output "web_servers" {
  value = { for s in huaweicloud_compute_instance.web : s.name => s.access_ip_v4 }
}

output "db_id" {
  value = huaweicloud_rds_instance.db.id
}

output "db_address" {
  value = huaweicloud_rds_instance.db.private_ips[0]
}

output "nat_public_ip" {
  value = huaweicloud_vpc_eip.nat.address
}

output "bucket" {
  value = huaweicloud_obs_bucket.assets.bucket
}

output "kms_key_id" {
  value = huaweicloud_kms_key.app.id
}

output "nat_gateway_id" {
  value = huaweicloud_nat_gateway.main.id
}

output "web_server_count" {
  value = var.web_servers
}
