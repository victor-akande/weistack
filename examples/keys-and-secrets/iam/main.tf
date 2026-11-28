# Step 3: the administrator sets up who may do what, once.
#
# - keys-deployers build the stack: the network, the server, its key pair,
#   the secret and the bucket. Nothing in IAM.
# - keys-operators look at everything and change nothing. They can see
#   that the secret exists, but not read its value.
# - keys-app is the application itself: it may read secret values and
#   nothing else.
#
# Run with the administrator's keys (`weistack credentials` on the cloud
# machine). The access keys this creates are written to ../secrets/.

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

# The account itself: global services (OBS) are granted at its scope.
data "huaweicloud_account" "current" {}

locals {
  project_id = data.huaweicloud_identity_projects.region.projects[0].id
  # Each service's own system policy, granted in the region's project only.
  # KPS and CSMS are part of DEW, and have their own.
  deployer_roles = [
    "VPC FullAccess", "ECS FullAccess", "EVS FullAccess", "IMS ReadOnlyAccess",
    "KMS Administrator", "CSMS FullAccess", "DEW KeypairFullAccess",
  ]
}

data "huaweicloud_identity_role" "deployer" {
  for_each     = toset(local.deployer_roles)
  display_name = each.value
}

data "huaweicloud_identity_role" "obs_admin" {
  display_name = "OBS Administrator"
}

data "huaweicloud_identity_role" "read_only" {
  display_name = "Tenant Guest"
}

# ---- deployers --------------------------------------------------------------

resource "huaweicloud_identity_group" "deployers" {
  name        = "keys-deployers"
  description = "Build and change the keys-and-secrets stack"
}

resource "huaweicloud_identity_group_role_assignment" "deployers" {
  for_each   = data.huaweicloud_identity_role.deployer
  group_id   = huaweicloud_identity_group.deployers.id
  role_id    = each.value.id
  project_id = local.project_id
}

# OBS is a global service, so its role is granted for the account.
resource "huaweicloud_identity_group_role_assignment" "deployers_obs" {
  group_id  = huaweicloud_identity_group.deployers.id
  role_id   = data.huaweicloud_identity_role.obs_admin.id
  domain_id = data.huaweicloud_account.current.id
}

# ---- operators --------------------------------------------------------------

resource "huaweicloud_identity_group" "operators" {
  name        = "keys-operators"
  description = "Look at the keys-and-secrets stack, change nothing"
}

resource "huaweicloud_identity_group_role_assignment" "operators" {
  group_id   = huaweicloud_identity_group.operators.id
  role_id    = data.huaweicloud_identity_role.read_only.id
  project_id = "all"
}

# ---- the application --------------------------------------------------------

# Reading a secret's value takes two permissions: CSMS's, to read the
# version, and KMS's, to decrypt the data key that encrypts it. The app
# gets exactly those. (Tenant Guest has the first but not the second, so
# operators cannot read values.)
resource "huaweicloud_identity_role" "read_secrets" {
  name        = "keys-app-read-secrets"
  type        = "XA"
  description = "Read secret values, and nothing else"
  policy = jsonencode({
    Version = "1.1"
    Statement = [{
      Effect = "Allow"
      Action = ["csms:secret:get", "csms:secretVersion:get", "kms:dek:decrypt"]
    }]
  })
}

resource "huaweicloud_identity_group" "apps" {
  name        = "keys-apps"
  description = "The keys-and-secrets application"
}

resource "huaweicloud_identity_group_role_assignment" "apps" {
  group_id   = huaweicloud_identity_group.apps.id
  role_id    = huaweicloud_identity_role.read_secrets.id
  project_id = local.project_id
}

# ---- users and their keys -----------------------------------------------------

resource "huaweicloud_identity_user" "deployer" {
  name        = "keys-deployer"
  description = "Deploys the stack (Terraform, CI)"
  access_type = "programmatic"
}

resource "huaweicloud_identity_user" "operator" {
  name        = "keys-operator"
  description = "Watches the stack"
  password    = var.operator_password
}

resource "huaweicloud_identity_user" "app" {
  name        = "keys-app"
  description = "The application: reads its secrets at start"
  access_type = "programmatic"
}

resource "huaweicloud_identity_group_membership" "deployers" {
  group = huaweicloud_identity_group.deployers.id
  users = [huaweicloud_identity_user.deployer.id]
}

resource "huaweicloud_identity_group_membership" "operators" {
  group = huaweicloud_identity_group.operators.id
  users = [huaweicloud_identity_user.operator.id]
}

resource "huaweicloud_identity_group_membership" "apps" {
  group = huaweicloud_identity_group.apps.id
  users = [huaweicloud_identity_user.app.id]
}

resource "huaweicloud_identity_access_key" "deployer" {
  user_id     = huaweicloud_identity_user.deployer.id
  description = "keys-and-secrets deploys"
  secret_file = "${path.module}/../secrets/deployer.csv"
}

resource "huaweicloud_identity_access_key" "operator" {
  user_id     = huaweicloud_identity_user.operator.id
  description = "keys-and-secrets operations"
  secret_file = "${path.module}/../secrets/operator.csv"
}

resource "huaweicloud_identity_access_key" "app" {
  user_id     = huaweicloud_identity_user.app.id
  description = "keys-and-secrets application"
  secret_file = "${path.module}/../secrets/app.csv"
}

output "project_id" {
  value = local.project_id
}
