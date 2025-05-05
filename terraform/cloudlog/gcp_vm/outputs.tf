output "agent_host_instance_id" {
  value = google_compute_instance.agent_host.instance_id
}

output "agent_host_name" {
  value = google_compute_instance.agent_host.name
}

output "firewall_name" {
  value = google_compute_firewall.allow_ssh.name
}

output "zone" {
  value = google_compute_instance.agent_host.zone
}


output "agent_host_private_ip" {
  value = google_compute_instance.agent_host.network_interface.0.network_ip
}

output "agent_host_public_ip" {
  value = google_compute_instance.agent_host.network_interface.0.access_config.0.nat_ip
}
