# Agencies through both API generations: a classic agency for a cloud
# service, granted roles in every scope, and an IAM 5.0 trust agency that
# the account may assume, with an identity policy attached.

resource "huaweicloud_identity_agency" "evs" {
  name                   = "tf-evs"
  description            = "EVS encrypts disks"
  delegated_service_name = "op_svc_evs"
  duration               = "ONEDAY"

  project_role {
    project = "ap-southeast-1"
    roles   = ["Tenant Guest"]
  }
  domain_roles        = ["OBS ReadOnlyAccess"]
  all_resources_roles = ["ECS FullAccess"]

  enterprise_project_roles {
    enterprise_project = "default"
    roles              = ["VPC ReadOnlyAccess"]
  }
}

resource "huaweicloud_identity_trust_agency" "deployer" {
  name        = "tf-deployer"
  description = "Deploys from CI"
  duration    = 7200
  trust_policy = jsonencode({
    Version = "5.0"
    Statement = [{
      Effect    = "Allow"
      Action    = ["sts:agencies:assume"]
      Principal = { IAM = [var.account_id] }
    }]
  })
  policy_names = [huaweicloud_identityv5_policy.readers.name]
}

output "agencies" {
  value = {
    classic_duration = huaweicloud_identity_agency.evs.duration
    trust_urn        = huaweicloud_identity_trust_agency.deployer.urn
  }
}
