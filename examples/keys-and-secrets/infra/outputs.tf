output "server_id" {
  value = huaweicloud_compute_instance.bastion.id
}

output "volume_id" {
  value = huaweicloud_compute_instance.bastion.system_disk_id
}

output "security_group_id" {
  value = huaweicloud_networking_secgroup.bastion.id
}

output "vpc_id" {
  value = huaweicloud_vpc.main.id
}

output "eip_id" {
  value = huaweicloud_vpc_eip.bastion.id
}

output "eip_address" {
  value = huaweicloud_vpc_eip.bastion.address
}

output "keypair" {
  value = huaweicloud_kps_keypair.bastion.name
}

output "keypair_fingerprint" {
  value = huaweicloud_kps_keypair.bastion.fingerprint
}

output "secret_name" {
  value = huaweicloud_csms_secret.api_token.name
}

output "secret_id" {
  value = huaweicloud_csms_secret.api_token.secret_id
}

output "kms_key_id" {
  value = huaweicloud_kms_key.app.id
}

output "bucket" {
  value = huaweicloud_obs_bucket.config.bucket
}
