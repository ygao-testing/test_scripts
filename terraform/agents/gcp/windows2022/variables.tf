resource "random_password" "pswd" {
  length    = 10
  special   = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "cnapp-445301"
}

variable "REGION" {
  description = "The GCP region"
  type        = string
  default     = "us-west1"
}

variable "ZONE" {
  description = "The GCP zone"
  type        = string
  default     = "us-west1-a"
}

variable "instance_name" {
  description = "Name of the Windows VM instance"
  type        = string
  default     = "windows-2022"
}

variable "machine_type" {
  description = "Machine type for the VM"
  type        = string
  default     = "n1-standard-2"
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 50
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

variable "USERNAME" {
  description = "Username tag"
  type        = string
  default     = "user"
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
