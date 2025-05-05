provider "lacework" {
}

provider "aws" {
  region  = "us-west-1"
}

module "aws_cloudtrail" {
  source  = "lacework/cloudtrail/aws"
  version = "~> 2.0"

  lacework_integration_name  = "fortiqa_cloudtrail"
}
