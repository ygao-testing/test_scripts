data "aws_region" "current" {}

locals {
  # Load the JSON data from the file
  test_files = jsondecode(file("${path.module}/../../agentless_files.json"))
}

data "template_file" "user-data-agent" {
  template = file("${path.root}/scripts/user-data-agent.tpl")
  vars = {
    "AGENLTESS_TEST_FILES" = jsonencode(local.test_files)
    "test_user_public_key" = var.PUBLIC_KEY
    "password"             = random_password.pswd.result
    "agent_access_token"   = var.AGENT_ACCESS_TOKEN
    "AGENTLESS_SCAN"       = var.AGENTLESS_SCAN
    "hostname"             = var.OWNER
  }
}

data "aws_ami" "collector_host_ami" {
 most_recent = true
 owners = ["amazon"]

 filter {
   name   = "owner-alias"
   values = ["amazon"]
 }

 filter {
   name   = "name"
   values = ["Windows_Server-2022-English-Full-Base*"]
 }
}

resource "aws_key_pair" "test_user_public_key" {
  key_name   = "${random_id.resource_prefix.hex}-test_user_public_key"
  public_key = var.PUBLIC_KEY
}

resource "aws_instance" "agent_host" {
  ami                    = data.aws_ami.collector_host_ami.id
  instance_type          = "t3.xlarge"
  availability_zone      = var.ZONE
  user_data              = data.template_file.user-data-agent.rendered
  key_name               = aws_key_pair.test_user_public_key.key_name
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-compute"
  }
}
