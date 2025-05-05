variable "ROLE_PREFIX" {
  default = "role-"
}

variable "ROLE_NAMES" {
  type    = list(string)
  default = ["role1", "role2", "role3", "role4", "role5", "role6", "role7"]
}

variable "OWNER" {
  type        = string
  description = "It will be used to add Owner label to each resource."
}

variable "REGION" {
  type    = string
  default = "us-central1"
}

variable "PROJECT_ID" {
  type        = string
  description = "GCP Project ID where resources will be created"
  default = "cnapp-445301"
}

resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix      = "${var.OWNER}-"
}

variable "RESOURCE_TAGS" {
  description = "Dynamic tags for resources"
  type        = map(string)
  default     = {}
}

variable "TERRAFORM_BACKEND_BUCKET" {
  type        = string
  description = "GCS bucket name for terraform backend"
  default     = "lacework-terraform-state"
}
