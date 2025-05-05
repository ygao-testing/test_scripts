data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  available_zones = data.aws_availability_zones.available.names
}

variable USER_PREFIX{
    default = "identity-"
}

variable USER_NAME {
    default = ["user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "user10","user11","user12","user13","user14"]
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner tag to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable REGION {
  type = string
  default = "us-east-2"
}
resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix = "${var.OWNER}-"
}
variable "INGESTION_TAG" {
  description = "Dynamic tags for resources"
  type        = map(string)
  default     = {}
}
