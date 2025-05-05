output "instance_name" {
  description = "Name of the VM instance"
  value       = google_compute_instance.agent_host.name
}

output "agent_host_public_ip" {
  description = "Public IP address of the VM"
  value       = google_compute_instance.agent_host.network_interface[0].access_config[0].nat_ip
}

output "agent_host_instance_id" {
  description = "The server instance ID"
  value       = google_compute_instance.agent_host.instance_id
}

output "Password" {
  description = "Password"
  value       = random_password.pswd.result
  sensitive   = true
}
