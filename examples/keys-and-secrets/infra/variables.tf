variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "project_id" {
  type        = string
  description = "The region's project ID (step 3's output)."
}

variable "name" {
  type        = string
  default     = "keys"
  description = "Prefix of every resource's name."
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "flavor" {
  type    = string
  default = "s6.medium.2"
}

variable "admin_cidr" {
  type        = string
  default     = "10.0.0.0/8"
  description = "The network allowed to SSH into the bastion."
}

variable "bucket" {
  type        = string
  default     = "keys-prod-config"
  description = "The configuration bucket. Bucket names are global: pick your own."
}
