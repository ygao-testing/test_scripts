provider "lacework" {
}

# Define variables for the alert profile
variable "alert_profile_name" {
  description = "Name of the Lacework alert profile"
  type        = string
  default     = "CUSTOM_PROFILE_TERRAFORM_TEST"
}

variable "extends_profile" {
  description = "Base profile to extend"
  type        = string
  default     = "LW_CFG_GCP_DEFAULT_PROFILE"
}

variable "alert_name" {
  description = "Name of the alert"
  type        = string
  default     = "TestViolation"
}

variable "event_name" {
  description = "Event name for the alert"
  type        = string
  default     = "TEST LW GCP Violation Alert"
}

variable "subject" {
  description = "Subject of the alert"
  type        = string
  default     = "test violation in project"
}

variable "description" {
  description = "Description of the alert"
  type        = string
  default     = "lacework_test_alert_profile"
}

# Create a Lacework alert profile
resource "lacework_alert_profile" "example" {
  name    = var.alert_profile_name
  extends = var.extends_profile

  alert {
    name        = var.alert_name
    event_name  = var.event_name
    subject     = var.subject
    description = var.description
  }
}
