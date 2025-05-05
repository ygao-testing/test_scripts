terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  backend "s3" {

  }
}

provider "google" {
  project = var.PROJECT_ID
  region  = var.REGION

  # Adding longer timeouts to handle potential race conditions
  user_project_override = true
  request_timeout       = "60s"
}
