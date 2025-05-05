terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}


data "template_file" "windows-data-agent" {
  template = file("${path.root}/scripts/windows-data-agent.ps1")
  vars = {
    "username" = var.USERNAME
    "agent_access_token" = var.AGENT_ACCESS_TOKEN
    "agentless_scan" = var.AGENTLESS_SCAN
  }
}

# Create Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "${var.instance_name}-rg"
  location = var.REGION

  tags = {
    environment = var.ENVIRONMENT
    owner       = var.OWNER
  }
}

# Create Virtual Network
resource "azurerm_virtual_network" "vnet" {
  name                = "${var.instance_name}-vnet"
  address_space       = ["10.0.0.0/16"]
  location           = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# Create Subnet
resource "azurerm_subnet" "subnet" {
  name                 = "${var.instance_name}-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Create Public IP
resource "azurerm_public_ip" "publicip" {
  name                = "${var.instance_name}-publicip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Create Network Security Group
resource "azurerm_network_security_group" "nsg" {
  name                = "${var.instance_name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "RDP"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range         = "*"
    destination_port_range    = "3389"
    source_address_prefix     = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "SSH"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range         = "*"
    destination_port_range    = "22"
    source_address_prefix     = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "WinRM"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range         = "*"
    destination_port_ranges   = ["5985", "5986"]
    source_address_prefix     = "*"
    destination_address_prefix = "*"
  }
}

# Create Network Interface
resource "azurerm_network_interface" "nic" {
  name                = "${var.instance_name}-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.publicip.id
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "nsg_association" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Create Windows VM
resource "azurerm_windows_virtual_machine" "vm" {
  name                  = var.instance_name
  computer_name         = var.OWNER
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = var.machine_type
  admin_username        = "azureuser"
  admin_password        = random_password.pswd.result
  network_interface_ids = [azurerm_network_interface.nic.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter"
    version   = "latest"
  }

  tags = {
    environment = var.ENVIRONMENT
    owner       = var.OWNER
  }
}

resource "azurerm_virtual_machine_extension" "windows-data-agent" {
  name                 = "windows-data-agent"
  virtual_machine_id   = azurerm_windows_virtual_machine.vm.id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"

  settings = <<SETTINGS
    {
        "commandToExecute": "powershell -command \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${base64encode(data.template_file.windows-data-agent.rendered)}')) | Out-File -Encoding UTF8 -FilePath agent-install.ps1\" && powershell -ExecutionPolicy Unrestricted -File agent-install.ps1"
    }
  SETTINGS
}
