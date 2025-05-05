resource "azurerm_role_definition" "custom_role_1" {
  name        = "${random_id.resource_prefix.hex}-custom-role-1"
  scope       = azurerm_resource_group.rg.id
  description = "Custom role 1 for managing specific operations in the resource group"
  permissions {
    actions = [
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Compute/virtualMachines/read"
    ]
    not_actions = []
  }
  assignable_scopes = [
    azurerm_resource_group.rg.id
  ]
}

resource "azurerm_role_definition" "custom_role_2" {
  name        = "${random_id.resource_prefix.hex}-custom-role-2"
  scope       = azurerm_resource_group.rg.id
  description = "Custom role 2 for managing other specific operations in the resource group"
  permissions {
    actions = [
      "Microsoft.Network/networkInterfaces/read",
      "Microsoft.Network/publicIPAddresses/read"
    ]
    not_actions = []
  }
  assignable_scopes = [
    azurerm_resource_group.rg.id
  ]
}

resource "azurerm_role_definition" "custom_role_3" {
  name        = "${random_id.resource_prefix.hex}-custom-role-3"
  scope       = azurerm_resource_group.rg.id
  description = "Custom role 3 for managing other specific operations in the resource group"
  permissions {
    actions = [
      "Microsoft.Network/networkInterfaces/read",
      "Microsoft.Compute/virtualMachines/read"
    ]
    not_actions = []
  }
  assignable_scopes = [
    azurerm_resource_group.rg.id
  ]
}
