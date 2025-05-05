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
    "AGENTLESS_SCAN"       = var.AGENTLESS_SCAN
    "hostname"             = var.OWNER
    "test_user_public_key" = var.PUBLIC_KEY
  }
}

resource "aws_key_pair" "test_user_public_key" {
  key_name   = "${random_id.resource_prefix.hex}-test_user_public_key"
  public_key = var.PUBLIC_KEY
}

data "aws_ami" "alpine" {
  most_recent = true
  owners      = ["538276064493"]

  filter {
    name   = "name"
    values = ["alpine-3.20.6-x86_64-uefi-cloudinit-r0"]
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

resource "aws_instance" "alpine" {
  ami                    = data.aws_ami.alpine.id
  instance_type          = "t3.small"
  availability_zone      = local.available_zones[0]
  user_data              = data.template_file.user-data-agent.rendered
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-alpine3.20"
  }
}
