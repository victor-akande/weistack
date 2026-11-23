# Step 3: the administrator sets up who may do what, once.
#
# - web-app-deployers may build and change the stack, service by service,
#   and nothing in IAM.
# - web-app-operators may look at everything and change nothing.
# - One user in each group: the deployer signs with an access key (CI,
#   Terraform); the operator also signs in with a password (curl, tokens).
#
# Run with the administrator's keys (`weistack credentials` on the cloud
# machine). The keys this creates are written to ../secrets/.

terraform {
  required_version = ">= 1.6"
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = "1.100.0"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "operator_password" {
  type        = string
  sensitive   = true
  description = "The operator's sign-in password."
}

provider "huaweicloud" {
  region = var.region
  # Keys come from HW_ACCESS_KEY and HW_SECRET_KEY.
}

data "huaweicloud_identity_projects" "region" {
  name = var.region
}

locals {
  project_id = data.huaweicloud_identity_projects.region.projects[0].id
  # Each service's own system role, granted in the region's project only.
  deployer_roles = [
    "VPC FullAccess", "ECS FullAccess", "EVS FullAccess", "IMS ReadOnlyAccess",
    "ELB FullAccess", "NAT FullAccess", "RDS FullAccess", "KMS Administrator",
  ]
}

data "huaweicloud_identity_role" "deployer" {
  for_each     = toset(local.deployer_roles)
  display_name = each.value
}

# The account itself: global services (OBS) are granted at its scope.
data "huaweicloud_account" "current" {}

data "huaweicloud_identity_role" "obs_admin" {
  display_name = "OBS Administrator"
}

data "huaweicloud_identity_role" "read_only" {
  display_name = "Tenant Guest"
}

resource "huaweicloud_identity_group" "deployers" {
  name        = "web-app-deployers"
  description = "Build and change the web app's stack"
}

resource "huaweicloud_identity_group_role_assignment" "deployers" {
  for_each   = data.huaweicloud_identity_role.deployer
  group_id   = huaweicloud_identity_group.deployers.id
  role_id    = each.value.id
  project_id = local.project_id
}

# OBS is a global service, so its role is granted for the account, not
# for a project.
resource "huaweicloud_identity_group_role_assignment" "deployers_obs" {
  group_id  = huaweicloud_identity_group.deployers.id
  role_id   = data.huaweicloud_identity_role.obs_admin.id
  domain_id = data.huaweicloud_account.current.id
}

resource "huaweicloud_identity_group" "operators" {
  name        = "web-app-operators"
  description = "Look at the web app's stack, change nothing"
}

resource "huaweicloud_identity_group_role_assignment" "operators" {
  group_id   = huaweicloud_identity_group.operators.id
  role_id    = data.huaweicloud_identity_role.read_only.id
  project_id = "all"
}

resource "huaweicloud_identity_user" "deployer" {
  name        = "web-app-deployer"
  description = "Deploys the web app (Terraform, CI)"
  access_type = "programmatic"
}

resource "huaweicloud_identity_user" "operator" {
  name        = "web-app-operator"
  description = "Watches the web app"
  password    = var.operator_password
}

resource "huaweicloud_identity_group_membership" "deployers" {
  group = huaweicloud_identity_group.deployers.id
  users = [huaweicloud_identity_user.deployer.id]
}

resource "huaweicloud_identity_group_membership" "operators" {
  group = huaweicloud_identity_group.operators.id
  users = [huaweicloud_identity_user.operator.id]
}

resource "huaweicloud_identity_access_key" "deployer" {
  user_id     = huaweicloud_identity_user.deployer.id
  description = "web-app deploys"
  secret_file = "${path.module}/../secrets/deployer.csv"
}

resource "huaweicloud_identity_access_key" "operator" {
  user_id     = huaweicloud_identity_user.operator.id
  description = "web-app operations"
  secret_file = "${path.module}/../secrets/operator.csv"
}

output "project_id" {
  value = local.project_id
}
