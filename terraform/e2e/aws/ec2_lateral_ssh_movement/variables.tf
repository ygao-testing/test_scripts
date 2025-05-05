data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  available_zones = data.aws_availability_zones.available.names
}

resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix = "${var.OWNER}-"
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner and Name tags to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable REGION {
  type = string
  default = "us-east-1"
}

variable public_subnet {
  type = string
  default = "10.1.61.0/24"
}

variable ZONE {
  type = string
  default = "us-east-1a"
}

variable PUBLIC_KEY {
  type = string
}
variable "INGESTION_TAG" {
  description = "Dynamic tags for resources"
  type        = map(string)
  default     = {}
}
