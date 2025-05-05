
data "template_file" "user_data_agent" {
  template = file("${path.root}/scripts/user-data-agent.tpl")
  vars = {
    agent_download_url = var.AGENT_DOWNLOAD_URL
  }
}
# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "${random_id.resource_prefix.hex}-resource-group"
  location = var.AZURE_REGION
  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-resource-group"
  })
}

# Virtual Network
resource "azurerm_virtual_network" "vnet" {
  name                = "${random_id.resource_prefix.hex}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-vnet"
  })
}

# Subnet
resource "azurerm_subnet" "subnet" {
  name                 = "${random_id.resource_prefix.hex}-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]

}

# Public IP for VM2
resource "azurerm_public_ip" "public_ip_vm2" {
  name                = "${random_id.resource_prefix.hex}-public-ip-vm2"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-public-ip-vm2"
  })
}

# Network Interface for VM1 (Private IP Only)
resource "azurerm_network_interface" "nic_vm1" {
  name                = "${random_id.resource_prefix.hex}-nic-vm1"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.0.1.4"
  }
  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-nic-vm1"
  })
}

# Network Interface for VM2 (Private and Public IP)
resource "azurerm_network_interface" "nic_vm2" {
  name                = "${random_id.resource_prefix.hex}-nic-vm2"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.0.1.5"
    public_ip_address_id          = azurerm_public_ip.public_ip_vm2.id
  }
  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-nic-vm2"
  })
}

# VM1 (Private IP Only)
resource "azurerm_linux_virtual_machine" "vm1" {
  name                  = "${random_id.resource_prefix.hex}-webserver1"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = "Standard_B1s"
  network_interface_ids = [azurerm_network_interface.nic_vm1.id]
  computer_name         = "webserver1"
  admin_username        = "azureuser"
  disable_password_authentication = true

  os_disk {
    caching              = "ReadWrite" # Default caching mode
    storage_account_type = "Standard_LRS" # Default disk type
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
  admin_ssh_key {
  username   = "azureuser"
  public_key = var.PUBLIC_KEY
}


  custom_data = base64encode(data.template_file.user_data_agent.rendered)
  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-webserver1"
  })
}
# VM2 (Private and Public IP)
resource "azurerm_linux_virtual_machine" "vm2" {
  name                  = "${random_id.resource_prefix.hex}-webserver2"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = "Standard_B1s"
  network_interface_ids = [azurerm_network_interface.nic_vm2.id]
  computer_name         = "webserver2"
  admin_username        = "azureuser"
  disable_password_authentication = true

  os_disk {
    caching              = "ReadWrite" # Default caching mode
    storage_account_type = "Standard_LRS" # Default disk type
  }

source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
 admin_ssh_key {
  username   = "azureuser"
  public_key = var.PUBLIC_KEY
}


  tags = merge(var.INGESTION_TAG, {
    Owner = var.OWNER,
    Name  = "${random_id.resource_prefix.hex}-webserver2"
  })
}
