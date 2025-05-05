provider "lacework" {
}

provider "aws" {
  region  = "us-west-1"
}

module "lacework_aws_agentless_scanning_singleregion" {
  source  = "lacework/agentless-scanning/aws"
  version = "~> 0.18"

  global                    = true
  regional                  = true
  lacework_integration_name = "fortiqa_agentless"
  scan_frequency_hours      = 6
}
