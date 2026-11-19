# Run by run.sh after the main scenario is applied, signing with the key
# of the IAM 5.0 user it made (tf-ops), whose identity policy allows only
# OBS and VPC reads. It reads the scenario's VPCs, which the policy
# allows. Under -iam=enforce, run.sh then asks for what the policy does
# not allow, a VPC (create_vpc) and a list of ECS servers (read_ecs), and
# expects both to be denied.

terraform {
  required_version = ">= 1.6"
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = "1.100.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "The emulator account's project."
}

variable "access_key" {
  type        = string
  description = "tf-ops's access key."
}

variable "secret_key" {
  type        = string
  sensitive   = true
  description = "Its secret key."
}

variable "create_vpc" {
  type        = bool
  default     = false
  description = "Ask for a VPC, which the policy does not allow."
}

variable "read_ecs" {
  type        = bool
  default     = false
  description = "List ECS servers, which the policy does not allow."
}

provider "huaweicloud" {
  region     = "ap-southeast-1"
  access_key = var.access_key
  secret_key = var.secret_key
  project_id = var.project_id

  skip_check_website_type = true
  skip_check_upgrade      = true
  max_retries             = 0
  insecure                = true
}

data "huaweicloud_vpcs" "all" {}

resource "huaweicloud_vpc" "denied" {
  count = var.create_vpc ? 1 : 0
  name  = "tf-ops-denied"
  cidr  = "10.9.0.0/16"
}

data "huaweicloud_compute_instances" "denied" {
  count = var.read_ecs ? 1 : 0
}

output "vpcs" {
  value = length(data.huaweicloud_vpcs.all.vpcs)
}
