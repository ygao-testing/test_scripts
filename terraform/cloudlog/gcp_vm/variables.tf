resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix = "${var.OWNER}-"
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner and Name tags to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable PUBLIC_KEY {
  type = string
}

variable GCP_PROJECT_ID {
  type = string
  default = "cnapp-e2e"
}
