terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}



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
