terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.REGION

  default_tags {
    tags = {
      Owner = var.OWNER
    }
  }

  ignore_tags {
    keys = ["Owner"]
  }
}
