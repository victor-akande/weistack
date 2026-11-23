# Per-service quota data sources.

data "huaweicloud_vpc_quotas" "vpc" {
  type = "vpc"

  depends_on = [
    huaweicloud_vpc.main,
    huaweicloud_vpc.nat_transit,
  ]
}

data "huaweicloud_elb_quotas" "all" {}

data "huaweicloud_evs_quotas" "all" {
  usage = "True"

  depends_on = [
    huaweicloud_compute_instance.web,
    huaweicloud_compute_instance.edge,
    huaweicloud_evs_volume.data,
    huaweicloud_evs_volume.encrypted,
    huaweicloud_evs_snapshot.data,
  ]
}

data "huaweicloud_compute_quotas" "all" {
  depends_on = [
    huaweicloud_compute_instance.web,
    huaweicloud_compute_instance.edge,
  ]
}

data "huaweicloud_ims_quotas" "all" {}

data "huaweicloud_rds_quotas" "all" {
  depends_on = [huaweicloud_rds_instance.db]
}

data "huaweicloud_identity_project_quota" "all" {
  project_id = var.project_id
}

output "quotas" {
  value = {
    vpc_quota           = data.huaweicloud_vpc_quotas.vpc.quotas[0].resources[0].quota
    vpc_used            = data.huaweicloud_vpc_quotas.vpc.quotas[0].resources[0].used
    elb_lb_quota        = data.huaweicloud_elb_quotas.all.loadbalancer
    elb_listener_quota  = data.huaweicloud_elb_quotas.all.listener
    evs_volumes_limit   = data.huaweicloud_evs_quotas.all.quota_set[0].volumes[0].limit
    evs_volumes_used    = data.huaweicloud_evs_quotas.all.quota_set[0].volumes[0].in_use
    evs_gigabytes_limit = data.huaweicloud_evs_quotas.all.quota_set[0].gigabytes[0].limit
    evs_gigabytes_used  = data.huaweicloud_evs_quotas.all.quota_set[0].gigabytes[0].in_use
    evs_snapshots_limit = data.huaweicloud_evs_quotas.all.quota_set[0].snapshots[0].limit
    evs_snapshots_used  = data.huaweicloud_evs_quotas.all.quota_set[0].snapshots[0].in_use
    ecs_instances_quota = data.huaweicloud_compute_quotas.all.absolute[0].max_total_instances
    ecs_instances_used  = data.huaweicloud_compute_quotas.all.absolute[0].total_instances_used
    ims_image_quota     = data.huaweicloud_ims_quotas.all.quotas[0].resources[0].quota
    ims_image_used      = data.huaweicloud_ims_quotas.all.quotas[0].resources[0].used
    rds_instance_quota  = data.huaweicloud_rds_quotas.all.quotas[0].resources[0].quota
    rds_instance_used   = data.huaweicloud_rds_quotas.all.quotas[0].resources[0].used
    iam_project_quota   = data.huaweicloud_identity_project_quota.all.resources[0].quota
    iam_project_used    = data.huaweicloud_identity_project_quota.all.resources[0].used
  }
}
