# Run by run.sh after the main scenario is applied: another account (the
# partner, whose root user's keys these are) assumes the agencies the
# scenario made for it, once through classic IAM (domain_name) and once
# through STS (domain_id), and reads the scenario's VPCs with each.

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
  description = "The emulator account's project, where the agencies act."
}

variable "account_id" {
  type        = string
  description = "The emulator's account, which made the agencies."
}

variable "account_name" {
  type        = string
  default     = "weistack"
  description = "Its name."
}

variable "partner_access_key" {
  type        = string
  description = "The partner account's root user's access key."
}

variable "partner_secret_key" {
  type        = string
  sensitive   = true
  description = "Its secret key."
}

provider "huaweicloud" {
  alias      = "classic"
  region     = "ap-southeast-1"
  access_key = var.partner_access_key
  secret_key = var.partner_secret_key
  project_id = var.project_id

  assume_role {
    agency_name = "tf-partner-ops"
    domain_name = var.account_name
  }

  skip_check_website_type = true
  skip_check_upgrade      = true
  max_retries             = 0
  insecure                = true
}

provider "huaweicloud" {
  alias      = "sts"
  region     = "ap-southeast-1"
  access_key = var.partner_access_key
  secret_key = var.partner_secret_key
  project_id = var.project_id

  assume_role {
    agency_name = "tf-deployer"
    domain_id   = var.account_id
  }

  skip_check_website_type = true
  skip_check_upgrade      = true
  max_retries             = 0
  insecure                = true
}

data "huaweicloud_vpcs" "classic" {
  provider = huaweicloud.classic
}

data "huaweicloud_vpcs" "sts" {
  provider = huaweicloud.sts
}

output "vpcs" {
  value = {
    classic = length(data.huaweicloud_vpcs.classic.vpcs)
    sts     = length(data.huaweicloud_vpcs.sts.vpcs)
  }
}
