resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix = "${var.OWNER}_"
}

resource "random_password" "pswd" {
  length    = 10
  special   = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

variable OWNER {
  type        = string
  description = "It will be used to add Owner and Name tags to each resource. Use your first name or user ID to make it easier for others to identify"
}

variable REGION {
  type = string
  default = "us-east-2"
}

variable ZONE {
  type = string
  default = "us-east-2a"
}

variable PUBLIC_KEY {
  type = string
}

variable AGENT_ACCESS_TOKEN {
  type      = string
  sensitive = true
}

variable AGENTLESS_SCAN {
  type = string
  default = "false"
}
