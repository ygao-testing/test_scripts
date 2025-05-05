provider "google" {
  project     = var.GCP_PROJECT_ID
  region      = "us-central1"
}

data "template_file" "user-data-agent" {
  template = file("${path.root}/scripts/user-data-agent.tpl")
  vars = {
    "agent_download_url"   = var.AGENT_DOWNLOAD_URL
    "test_user_public_key" = var.PUBLIC_KEY
    "AGENTLESS_SCAN"       = var.AGENTLESS_SCAN
    "hostname"             = var.OWNER
  }
}


resource "google_compute_instance" "agent_host" {
  name         = "${random_id.resource_prefix.hex}-ubuntu2204"
  machine_type = "n2-standard-2"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "ubuntu-2204-jammy-v20250219"
    }
  }

  // Local SSD disk
  scratch_disk {
    interface = "NVME"
  }

  network_interface {
    network = "default"
    access_config {
    }
  }

  # Install cloud-init if not available yet
  metadata_startup_script = <<-CLOUD_INIT
  #!/bin/bash
  command -v cloud-init &>/dev/null || (sudo apt-get update && sudo apt-get install -y cloud-init && sudo reboot)
  CLOUD_INIT

  metadata = {
    user-data = data.template_file.user-data-agent.rendered
  }

  # Allow SSH access
  tags = ["allow-ssh"]
}

# Create a firewall rule to allow SSH access
resource "google_compute_firewall" "allow_ssh" {
  name    = "${random_id.resource_prefix.hex}-allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Allow SSH access from anywhere
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["allow-ssh"]
}
