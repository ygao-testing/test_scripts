variable "OWNER" {
  description = "Owner tag for all resources"
  type        = string
}

variable "AZURE_REGION" {
  description = "Azure region to deploy resources"
  type        = string
  default     = "eastus"
}

# variable "INGESTION_TAG" {
#   description = "Global tags applied to all resources"
#   default = {Test  = "daily_ingestion"}
# }

resource "random_id" "resource_prefix" {
  byte_length = 4
  prefix      = "${var.OWNER}_"
}
variable PUBLIC_KEY {
  type = string
}
variable "INGESTION_TAG" {
  description = "Dynamic tags for resources"
  type        = map(string)
  default     = {}
}
variable "AGENT_DOWNLOAD_URL" {
  description = "URL to download the agent installation script"
  type        = string
}
