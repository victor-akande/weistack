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
  default     = "web-app"
  description = "Prefix of every resource's name."
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "web_servers" {
  type        = number
  default     = 2
  description = "How many web servers; they are spread across the zones."
}

variable "web_flavor" {
  type    = string
  default = "s6.medium.2"
}

variable "db_flavor" {
  type    = string
  default = "rds.mysql.n1.large.2"
}

variable "db_password" {
  type        = string
  sensitive   = true
  description = "The database root password (secrets/db-password)."
}

variable "bucket" {
  type        = string
  default     = "web-app-prod-assets"
  description = "The bucket's name; bucket names are unique per region."
}
