output "instance_name" {
  description = "Name of the VM instance"
  value       = azurerm_windows_virtual_machine.vm.id
}

output "agent_host_public_ip" {
  description = "Public IP address of the VM"
  value       = azurerm_public_ip.publicip.ip_address
}

output "agent_host_instance_id" {
  description = "The server instance ID"
  value       = azurerm_windows_virtual_machine.vm.virtual_machine_id
}

output "agent_host_private_ip" {
  description = "Private IP address of the VM"
  value       = azurerm_windows_virtual_machine.vm.private_ip_address
}

output "Password" {
  value = random_password.pswd.result
  sensitive = true
}
