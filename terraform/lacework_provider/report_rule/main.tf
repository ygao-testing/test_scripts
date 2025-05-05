resource "lacework_alert_channel_email" "team_email" {
  name       = "Team Emails"
  recipients = ["foo@example.com", "bar@example.com"]
}

variable "report_rule_name" {
  type        = string
  description = "The name of the report rule"
  default     = "My Report Rule"
}

resource "lacework_report_rule" "aws" {
  name                 = var.report_rule_name
  description          = "This is an example report rule"
  email_alert_channels = [lacework_alert_channel_email.team_email.id]
  severities           = ["Critical", "High"]

  aws_compliance_reports {
    cis_s3 = true
  }
}

resource "lacework_report_rule" "default" {
  name = "Daily Compliance Reports and Weekly Snapshot"
  severities = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Info"
  ]

  email_alert_channels = [
    lacework_alert_channel_email.team_email.id
  ]

  daily_compliance_reports {
    host_security  = true
    aws_cloudtrail = true
    aws_compliance = true
  }
}
