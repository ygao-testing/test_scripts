# Output the VM1 ID
output "vm1_id" {
  description = "Globally unique resource ID for VM1"
  value       = azurerm_linux_virtual_machine.vm1.id
}

# Output the VM2 ID
output "vm2_id" {
  description = "Globally unique resource ID for VM2"
  value       = azurerm_linux_virtual_machine.vm2.id
}

# Output the Resource Group name
output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.rg.name
}

# Output the Resource Group ID
output "resource_group_id" {
  description = "ID of the resource group"
  value       = azurerm_resource_group.rg.id
}

# Output the Virtual Network ID
output "vnet_id" {
  description = "ID of the virtual network"
  value       = azurerm_virtual_network.vnet.id
}

# Output the Public IP of VM2 (if it has one)
output "vm2_public_ip" {
  description = "Public IP address of VM2"
  value       = azurerm_public_ip.public_ip_vm2.ip_address
}
