resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix = "${var.OWNER}-"
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner and Name tags to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable AZURE_LOCATION {
  type = string
  default = "eastus"
}

variable PUBLIC_KEY {
  type = string
}
