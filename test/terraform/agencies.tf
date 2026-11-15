# Agencies through both API generations: a classic agency for a cloud
# service, granted roles in every scope, a classic agency for another
# account, and an IAM 5.0 trust agency that the account and the other
# one may assume, with an identity policy attached. run.sh adds the other
# account (the partner) and, once this is applied, assumes the agencies
# with its keys (assume/main.tf).

variable "partner_id" {
  type        = string
  description = "The partner account's ID (POST /_weistack/accounts)."
}

variable "partner_name" {
  type        = string
  description = "Its name."
}

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

resource "huaweicloud_identity_agency" "partner" {
  name                  = "tf-partner-ops"
  description           = "The partner reads our VPCs"
  delegated_domain_name = var.partner_name

  project_role {
    project = "ap-southeast-1"
    roles   = ["VPC ReadOnlyAccess"]
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
      Principal = { IAM = [var.account_id, var.partner_id] }
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
