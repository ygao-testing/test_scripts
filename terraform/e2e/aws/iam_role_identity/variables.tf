variable "ROLE_PREFIX" {
  default = "identity-role-"
}

variable "ROLE_NAMES" {
  default = ["role1", "role2", "role3", "role4", "role5", "role6", "role7", "role8", "role9", "role10", "role11", "role12", "role13", "role14"]
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
