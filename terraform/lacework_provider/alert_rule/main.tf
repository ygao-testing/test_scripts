provider "lacework" {
}

variable "alert_channel_name" {
  description = "Name of the Lacework alert channel"
  type        = string
  default     = "FORTIQA test email alert channel"
}

variable "alert_rule_name" {
  description = "Name of the Lacework alert rule"
  type        = string
  default     = "FORTIQA test alert rule"
}

resource "lacework_alert_channel_email" "fortiqa_test" {
  name       = var.alert_channel_name
  recipients = [
    "fcslwsysteme2e@yahoo.com",
  ]
}

resource "lacework_alert_rule" "example" {
  name                = var.alert_rule_name
  description         = "Automation test alert rule"
  alert_channels      = [lacework_alert_channel_email.fortiqa_test.id]
  severities          = ["Critical", "High", "Medium", "Low", "Info"]
  alert_subcategories = ["Compliance"]
  alert_categories    = ["Policy"]
  alert_sources       = ["AWS"]
}
# test adding sub categories - https://github.com/lacework/terraform-provider-lacework/issues/511
resource "lacework_alert_rule" "more_subcategories" {
  name                = "More Subcategories"
  description         = "test adding sub categories"
  alert_channels      = [lacework_alert_channel_email.fortiqa_test.id]
  severities          = ["Critical", "High", "Medium", "Low", "Info"]
  alert_subcategories = ["Compliance", "App", "Cloud", "File", "Machine", "User", "Platform", "K8sActivity"]
  alert_categories    = ["Policy"]
  alert_sources       = ["AWS"]
}
