resource "random_password" "pswd" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
}

variable "REGION" {
  description = "The Azure region"
  type        = string
  default     = "westus2"
}

variable "ZONE" {
  description = "The Azure zone"
  type        = string
  default     = "westus2"
}

variable "instance_name" {
  description = "Name of the Windows VM instance"
  type        = string
  default     = "windows-2016"
}

variable "machine_type" {
  description = "Machine type for the VM"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 127  # Minimum size required for Windows Server 2022 image
}

variable "ENVIRONMENT" {
  description = "Environment tag"
  type        = string
  default     = "dev"
}

variable "OWNER" {
  description = "Owner tag"
  type        = string
}

# use Public as the username for path in the script
variable "USERNAME" {
  description = "Username tag"
  type        = string
  default     = "Public"
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
