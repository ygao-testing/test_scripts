output "agent_host_instance_id" {
  value = azurerm_linux_virtual_machine.agent_vm.virtual_machine_id
}

output "agent_host_name" {
  value = azurerm_linux_virtual_machine.agent_vm.name
}

output "agent_virtual_network_name" {
  value = azurerm_virtual_network.agent_vnet.name
}

output "agent_subnet_name" {
  value = azurerm_subnet.agent_subnet.name
}

output "agent_resource_group_name" {
  value = azurerm_resource_group.agent_rg.name
}

output "agent_network_interface_name" {
  value = azurerm_network_interface.agent_nic.name
}
