provider "google" {
  project     = var.GCP_PROJECT_ID
  region      = "us-central1"
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
