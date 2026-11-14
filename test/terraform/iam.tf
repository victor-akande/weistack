# IAM through both API generations: classic IAM's users, groups,
# permissions and access keys, and IAM 5.0's users, groups, identity
# policies and access keys. Everything here is account-wide.

variable "account_id" {
  type        = string
  description = "The emulator's account (domain) ID (GET /_weistack/services)."
}

variable "iam_password" {
  type        = string
  sensitive   = true
  description = "The classic IAM user's password. run.sh generates one per run."
}

# Classic IAM.

resource "huaweicloud_identity_user" "dev" {
  name        = "tf-dev"
  description = "A developer"
  email       = "dev@example.com"
  password    = var.iam_password
}

resource "huaweicloud_identity_group" "devs" {
  name        = "tf-devs"
  description = "Developers"
}

resource "huaweicloud_identity_group_membership" "devs" {
  group = huaweicloud_identity_group.devs.id
  users = [huaweicloud_identity_user.dev.id]
}

# A system role, found as users find one: by display name.
data "huaweicloud_identity_role" "ecs_full" {
  display_name = "ECS FullAccess"
}

data "huaweicloud_identity_role" "tenant_guest" {
  display_name = "Tenant Guest"
}

resource "huaweicloud_identity_role" "bucket_reader" {
  name        = "tf-bucket-reader"
  description = "Reads bucket ACLs"
  type        = "AX"
  policy = jsonencode({
    Version = "1.1"
    Statement = [{
      Effect   = "Allow"
      Action   = ["obs:bucket:GetBucketAcl"]
      Resource = ["obs:*:*:bucket:*"]
    }]
  })
}

# Grants in every scope: one project, all projects, global services and
# the default enterprise project.
resource "huaweicloud_identity_group_role_assignment" "project" {
  group_id   = huaweicloud_identity_group.devs.id
  role_id    = data.huaweicloud_identity_role.ecs_full.id
  project_id = var.project_id
}

resource "huaweicloud_identity_group_role_assignment" "all_projects" {
  group_id   = huaweicloud_identity_group.devs.id
  role_id    = data.huaweicloud_identity_role.tenant_guest.id
  project_id = "all"
}

resource "huaweicloud_identity_group_role_assignment" "domain" {
  group_id  = huaweicloud_identity_group.devs.id
  role_id   = huaweicloud_identity_role.bucket_reader.id
  domain_id = var.account_id
}

resource "huaweicloud_identity_group_role_assignment" "enterprise_project" {
  group_id              = huaweicloud_identity_group.devs.id
  role_id               = huaweicloud_identity_role.bucket_reader.id
  enterprise_project_id = "0"
}

resource "huaweicloud_identity_user_role_assignment" "dev" {
  user_id               = huaweicloud_identity_user.dev.id
  role_id               = huaweicloud_identity_role.bucket_reader.id
  enterprise_project_id = "0"
}

resource "huaweicloud_identity_access_key" "dev" {
  user_id     = huaweicloud_identity_user.dev.id
  description = "CI key"
  # Kept with the state, in run.sh's working directory.
  secret_file = "${path.module}/tf-dev-credentials.csv"
}

# IAM 5.0.

resource "huaweicloud_identityv5_user" "ops" {
  name        = "tf-ops"
  description = "An operator"
}

resource "huaweicloud_identityv5_group" "ops" {
  group_name  = "tf-ops"
  description = "Operators"
}

resource "huaweicloud_identityv5_group_membership" "ops" {
  group_id     = huaweicloud_identityv5_group.ops.id
  user_id_list = [huaweicloud_identityv5_user.ops.id]
}

resource "huaweicloud_identityv5_policy" "readers" {
  name        = "tf-readers"
  path        = "tf/"
  description = "Read-only access to OBS and VPC"
  policy_document = jsonencode({
    Version = "5.0"
    Statement = [{
      Effect   = "Allow"
      Action   = ["obs:*:get*", "obs:*:list*", "vpc:*:get*", "vpc:*:list*"]
      Resource = ["*"]
    }]
  })
}

resource "huaweicloud_identityv5_policy_user_attach" "ops" {
  policy_id = huaweicloud_identityv5_policy.readers.id
  user_id   = huaweicloud_identityv5_user.ops.id
}

resource "huaweicloud_identityv5_policy_group_attach" "ops" {
  policy_id = huaweicloud_identityv5_policy.readers.id
  group_id  = huaweicloud_identityv5_group.ops.id
}

resource "huaweicloud_identityv5_access_key" "ops" {
  user_id = huaweicloud_identityv5_user.ops.id
}

output "iam" {
  value = {
    v5_policy_type    = huaweicloud_identityv5_policy.readers.type
    access_key_status = huaweicloud_identity_access_key.dev.status
    v5_policy_version = huaweicloud_identityv5_policy.readers.default_version_id
    v5_key_status     = huaweicloud_identityv5_access_key.ops.status
  }
}
