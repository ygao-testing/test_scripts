provider "azurerm" {
  features {}
}

data "template_file" "user-data-agent" {
  template = file("${path.root}/scripts/user-data-agent.tpl")
  vars = {
    "agent_download_url"   = var.AGENT_DOWNLOAD_URL
    "agentless_scan"       = var.AGENTLESS_SCAN
    "hostname"             = var.OWNER
  }
}

# Create a resource group
resource "azurerm_resource_group" "agent_rg" {
  name     = "${random_id.resource_prefix.hex}-rg"
  location = var.AZURE_LOCATION

  tags = {
    Owner = var.OWNER
    Name  = "${random_id.resource_prefix.hex}-rg"
  }
}

# Create a virtual network
resource "azurerm_virtual_network" "agent_vnet" {
  name                = "${random_id.resource_prefix.hex}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.agent_rg.location
  resource_group_name = azurerm_resource_group.agent_rg.name

  tags = {
    Owner = var.OWNER
    Name  = "${random_id.resource_prefix.hex}-vnet"
  }
}

# Create a subnet
resource "azurerm_subnet" "agent_subnet" {
  name                 = "${random_id.resource_prefix.hex}-subnet"
  resource_group_name  = azurerm_resource_group.agent_rg.name
  virtual_network_name = azurerm_virtual_network.agent_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Create a public IP
resource "azurerm_public_ip" "agent_public_ip" {
  name                = "${random_id.resource_prefix.hex}-public-ip"
  location            = azurerm_resource_group.agent_rg.location
  resource_group_name = azurerm_resource_group.agent_rg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Owner = var.OWNER
    Name  = "${random_id.resource_prefix.hex}-public-ip"
  }
}

# Create a network security group
resource "azurerm_network_security_group" "agent_nsg" {
  name                = "${random_id.resource_prefix.hex}-nsg"
  location            = azurerm_resource_group.agent_rg.location
  resource_group_name = azurerm_resource_group.agent_rg.name

  # Allow SSH access
  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Owner = var.OWNER
    Name  = "${random_id.resource_prefix.hex}-nsg"
  }
}

# Create a network interface
resource "azurerm_network_interface" "agent_nic" {
  name                = "${random_id.resource_prefix.hex}-nic"
  location            = azurerm_resource_group.agent_rg.location
  resource_group_name = azurerm_resource_group.agent_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.agent_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.agent_public_ip.id
  }

  tags = {
    Owner = var.OWNER
    Name  = "${random_id.resource_prefix.hex}-nic"
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "agent_nic_nsg_association" {
  network_interface_id      = azurerm_network_interface.agent_nic.id
  network_security_group_id = azurerm_network_security_group.agent_nsg.id
}

# Create the virtual machine
resource "azurerm_linux_virtual_machine" "agent_vm" {
  name                = "${random_id.resource_prefix.hex}-ubuntu1604"
  resource_group_name = azurerm_resource_group.agent_rg.name
  location            = azurerm_resource_group.agent_rg.location
  size                = "Standard_D2s_v3"
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.agent_nic.id,
  ]

  admin_ssh_key {
    username   = "adminuser"
    public_key = var.PUBLIC_KEY
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS"
    version   = "latest"
  }

  custom_data = base64encode(data.template_file.user-data-agent.rendered)

  tags = {
    Owner = var.OWNER
    Name  = "${random_id.resource_prefix.hex}-ubuntu1604"
  }
}
