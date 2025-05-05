data "aws_region" "current" {}

data "template_file" "user-data-agent" {
  template = file("${path.root}/scripts/user-data-agent.tpl")
  vars = {
    "agent_download_url"   = var.AGENT_DOWNLOAD_URL
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
      name   = "name"
      values = ["ubuntu/images/hvm-ssd/ubuntu-*-22.04-amd64-server-*"]
  }

  filter {
      name   = "virtualization-type"
      values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "ec2_instance" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  availability_zone      = var.ZONE
  user_data              = data.template_file.user-data-agent.rendered
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.public_access.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-instance"
  }
}
