data "aws_region" "current" {}

locals {
  # Load the JSON data from the file
  test_files = jsondecode(file("${path.module}/../../agentless_files.json"))
}

data "template_file" "user-data-agent" {
  template = file("${path.root}/scripts/user-data-agent.tpl")
  vars = {
    "AGENLTESS_TEST_FILES" = jsonencode(local.test_files)
    "agent_download_url"   = var.AGENT_DOWNLOAD_URL
    "bastion_public_key"   = tls_private_key.bastion_keypair.public_key_openssh
    "test_user_public_key" = var.PUBLIC_KEY
    "AGENTLESS_SCAN"       = var.AGENTLESS_SCAN
    "hostname"             = var.OWNER
  }
}

data "aws_ami" "debian" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
      name   = "name"
      values = ["debian-11-amd64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
      name   = "virtualization-type"
      values = ["hvm"]
  }
}

resource "tls_private_key" "bastion_keypair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "bastion_public_key" {
  key_name = "${random_id.resource_prefix.hex}-bastion_public_key"
  public_key = tls_private_key.bastion_keypair.public_key_openssh
}

resource "aws_key_pair" "test_user_public_key" {
  key_name   = "${random_id.resource_prefix.hex}-test_user_public_key"
  public_key = var.PUBLIC_KEY
}

resource "aws_instance" "agent_host" {
  ami                    = data.aws_ami.debian.id
  instance_type          = "t3.small"
  availability_zone      = local.available_zones[0]
  user_data              = data.template_file.user-data-agent.rendered
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-debian11"
  }
}
