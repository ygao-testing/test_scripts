terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

locals {
  test_files = jsondecode(file("${path.module}/../../agentless_files.json"))
}

data "template_file" "windows-data-agent" {
  template = file("${path.root}/scripts/windows-data-agent.ps1")
  vars = {
    "AGENTLESS_TEST_FILES"  = jsonencode(local.test_files)
    "test_user_public_key" = var.PUBLIC_KEY
    "password"             = random_password.pswd.result
    "agent_access_token"   = var.AGENT_ACCESS_TOKEN
    "agentless_scan"       = var.AGENTLESS_SCAN
    "username"             = var.USERNAME
  }
}

provider "google" {
  project = var.project_id
  region  = var.REGION
  zone    = var.ZONE
}


# Create a Windows VM instance
resource "google_compute_instance" "agent_host" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.ZONE
  # https://cloud.google.com/compute/docs/instances/custom-hostname-vm#terraform
  hostname     = "${var.OWNER}.example.com"

  boot_disk {
    initialize_params {
      image = "windows-cloud/windows-server-2016-dc-core-v20250123"
      size  = var.disk_size_gb
    }
  }

  network_interface {
    network = "default"
    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    windows-startup-script-ps1 = data.template_file.windows-data-agent.rendered
  }

  tags = ["default-allow-rdp", "default-allow-ssh"]

  labels = {
    environment = var.ENVIRONMENT
    owner       = var.OWNER
  }
}
