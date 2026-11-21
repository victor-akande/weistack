# Standalone EVS volumes, volume attachment, encryption, snapshots, and EVS
# data sources.

variable "evs_size" {
  type        = number
  default     = 20
  description = "Size in GB of the standalone GPSSD volume; expanded in run.sh."
}

resource "huaweicloud_evs_volume" "data" {
  name              = "tf-evs-data"
  volume_type       = "GPSSD"
  size              = var.evs_size
  availability_zone = huaweicloud_compute_instance.web.availability_zone

  tags = {
    env = "test"
  }
}

resource "huaweicloud_compute_volume_attach" "data" {
  instance_id           = huaweicloud_compute_instance.web.id
  volume_id             = huaweicloud_evs_volume.data.id
  delete_on_termination = "false"
}

resource "huaweicloud_evs_volume" "encrypted" {
  name              = "tf-evs-encrypted"
  volume_type       = "SSD"
  size              = 10
  availability_zone = huaweicloud_compute_instance.web.availability_zone
  kms_id            = huaweicloud_kms_key.app.id
}

resource "huaweicloud_evs_snapshot" "data" {
  name      = "tf-evs-snap"
  volume_id = huaweicloud_evs_volume.data.id
  force     = true

  depends_on = [huaweicloud_compute_volume_attach.data]
}

data "huaweicloud_evs_volumes" "web" {
  server_id = huaweicloud_compute_instance.web.id

  depends_on = [huaweicloud_compute_volume_attach.data]
}

data "huaweicloud_evs_snapshots" "all" {
  volume_id = huaweicloud_evs_volume.data.id

  depends_on = [huaweicloud_evs_snapshot.data]
}

data "huaweicloud_evs_availability_zones" "all" {}

data "huaweicloud_evs_volume_types" "all" {}

output "evs" {
  value = {
    attached_status    = [for v in data.huaweicloud_evs_volumes.web.volumes : v.status if v.id == huaweicloud_evs_volume.data.id][0]
    encrypted_status   = huaweicloud_evs_volume.encrypted.status
    snapshot_status    = huaweicloud_evs_snapshot.data.status
    web_volumes_count  = length(data.huaweicloud_evs_volumes.web.volumes)
    snapshots_count    = length(data.huaweicloud_evs_snapshots.all.snapshots)
    has_azs            = length(data.huaweicloud_evs_availability_zones.all.availability_zones) > 0
    volume_types_count = length(data.huaweicloud_evs_volume_types.all.types)
  }
}
