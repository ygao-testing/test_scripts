provider "lacework" {
}

variable "resource_group_name" {
  description = "The name of the resource group"
  type        = string
  default     = "My Resource Group"
}

resource "lacework_resource_group" "example" {
  name        = var.resource_group_name
  type        = "AWS"
  description = "This groups a subset of AWS resources"
  group {
    operator = "OR"
    filter {
      filter_name = "filter1"
      field     = "Region"
      operation = "EQUALS"
      value     = ["us-east-1"]
    }

    filter {
      filter_name = "filter2"
      field     = "Region"
      operation = "EQUALS"
      value     = ["us-west-2"]
    }

    group {
      operator = "AND"

      filter {
        filter_name = "filter5"
        field     = "Region"
        operation = "EQUALS"
        value     = ["us-central-1"]
      }

      group {
        operator = "OR"
        filter {
          filter_name = "filter3"
          field     = "Account"
          operation = "EQUALS"
          value     = ["987654321"]
        }
        filter {
          filter_name = "filter4"
          field     = "Account"
          operation = "EQUALS"
          value     = ["123456789"]
        }
      }
    }
  }
}
