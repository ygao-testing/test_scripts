data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  available_zones = data.aws_availability_zones.available.names
}

variable ROLE_PREFIX{
    default = "lacework_test_"
}

variable ROLE_NAME {
    default = ["role1", "role2", "role3", "role4"]
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner and Name tags to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable REGION {
  type = string
  default = "us-west-1"
}
