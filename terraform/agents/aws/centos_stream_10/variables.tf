data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  available_zones = data.aws_availability_zones.available.names
}

resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix = "${var.OWNER}_"
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner and Name tags to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable bastion_subnet {
  type = string
  default = "10.1.61.0/24"
}

variable public_subnets {
  type = list
  default = ["10.1.71.0/24", "10.1.72.0/24"]
}

variable private_subnets {
  type = list
  default = ["10.1.81.0/24", "10.1.82.0/24"]
}

variable REGION {
  type = string
  default = "us-west-1"
}

variable PUBLIC_KEY {
  type = string
}

variable AGENT_DOWNLOAD_URL {
  type = string
}

variable AGENTLESS_SCAN {
  type = string
  default = "false"
}
