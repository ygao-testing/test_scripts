variable "GROUP_PREFIX" {
  default = "identity-group-"
}

variable "GROUP_NAMES" {
  default = ["group1", "group2", "group3", "group4", "group5", "group6", "group7", "group8", "group9", "group10", "group11", "group12", "group13", "group14"]
}

variable "OWNER" {
  type        = string
  description = "It will be used to add Owner tag to each resource."
}

variable "REGION" {
  type    = string
  default = "us-east-2"
}

resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix      = "${var.OWNER}-"
}

variable "INGESTION_TAG" {
  description = "Dynamic tags for resources"
  type        = map(string)
  default     = {}
}
