output "agent_host_instance_id" {
  value = azurerm_linux_virtual_machine.agent_vm.virtual_machine_id
}

output "agent_host_private_ip" {
  value = azurerm_linux_virtual_machine.agent_vm.private_ip_address
}

output "agent_host_public_ip" {
  value = azurerm_linux_virtual_machine.agent_vm.public_ip_address
}
