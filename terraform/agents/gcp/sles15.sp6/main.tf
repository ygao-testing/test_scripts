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
  }
}

resource "google_compute_instance" "agent_host" {
  name         = "${random_id.resource_prefix.hex}-sles15-sp6"
  machine_type = "n2-standard-2"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      # Using SLES 15 SP6 image
      image = "sles-15-sp6-v20250129-x86-64"
    }
  }

  scratch_disk {
    interface = "NVME"
  }

  network_interface {
    network = "default"
    access_config {
    }
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    if [ "${var.AGENTLESS_SCAN}" != "true" ]; then
    curl ${var.AGENT_DOWNLOAD_URL} -o install.sh
    chmod +x install.sh
    sudo ./install.sh &> ~/agent-install.log
    sudo mv ~/agent-install.log /var/log/
    else
    echo "Agentless scan enabled." >> ~/agent-install.log
    sudo mv ~/agent-install.log /var/log/
    fi
  EOT

  metadata = {
    ssh-keys  = "fcsqa:${var.PUBLIC_KEY}"  # Format: USERNAME:SSH_KEY
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
