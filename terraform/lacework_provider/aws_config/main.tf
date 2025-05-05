provider "lacework" {
}

provider "aws" {
  region  = "us-west-1"
}

module "aws_config" {
  source                     = "lacework/config/aws"
  version                    = "~> 0.15"
  lacework_integration_name  = "fortiqa_aws_config"
}
