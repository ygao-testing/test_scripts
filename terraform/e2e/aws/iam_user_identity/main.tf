terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {

  }
}


provider "aws" {
  region = var.REGION

  default_tags {
        tags = merge(
      {
        Owner = var.OWNER
      },
      var.INGESTION_TAG # Includes "Test" tag dynamically
    )
    }
  ignore_tags {
    keys = ["Owner"]
  }
}
