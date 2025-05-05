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
  name         = "${random_id.resource_prefix.hex}-centos-stream-8"
  machine_type = "n2-standard-2"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      # Using CentOS Stream 8 image
      # deprecated
      # gcloud compute images list --project cnapp --show-deprecated | grep centos-stream-8
      image = "centos-stream-8-v20240515"
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
      if [ ! -x "$(command -v cloud-init)" ]; then
        sudo sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/CentOS-*.repo
        sudo sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/CentOS-*.repo
        sudo sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/CentOS-*.repo
        sudo yum update
        sudo yum install -y cloud-init
        sudo reboot
      fi
    fi
  EOT

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
