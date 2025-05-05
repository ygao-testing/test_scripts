resource "lacework_query" "AWS_CTA_AuroraPasswordChange" {
  query_id = "TF_AWS_CTA_AuroraPasswordChange"
  query    = <<EOT
  {
      source {
          CloudTrailRawEvents
      }
      filter {
          EVENT_SOURCE = 'rds.amazonaws.com'
          and EVENT_NAME = 'ModifyDBCluster'
          and value_exists(EVENT:requestParameters.masterUserPassword)
          and EVENT:requestParameters.applyImmediately = true
          and ERROR_CODE is null
      }
      return distinct {
          INSERT_ID,
          INSERT_TIME,
          EVENT_TIME,
          EVENT
      }
  }
EOT
}

variable "policy_title" {
  description = "The title of the policy"
  type        = string
  default    = "Aurora Password Change"
}

resource "lacework_policy" "example" {
  title       = var.policy_title
  description = "Password for an Aurora RDS cluster was changed"
  remediation = "Check that the password change was expected and ensure only specified users can modify the RDS cluster"
  query_id    = lacework_query.AWS_CTA_AuroraPasswordChange.id
  severity    = "High"
  type        = "Violation"
  evaluation  = "Hourly"
  tags        = ["cloud_AWS", "custom"]
  enabled     = false

  alerting {
    enabled = false
    profile = "LW_CloudTrail_Alerts.CloudTrailDefaultAlert_AwsResource"
  }
}
