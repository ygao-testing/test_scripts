data "aws_region" "current" {}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
      name   = "name"
      values = ["ubuntu/images/hvm-ssd/ubuntu-*-20.04-amd64-server-*"]
  }

  filter {
      name   = "virtualization-type"
      values = ["hvm"]
  }

  owners = ["099720109477"]
}

resource "aws_key_pair" "test_user_public_key" {
  count      = 2
  key_name   = "${random_id.resource_prefix.hex}-test_user_public_key-${count.index}"
  public_key = var.PUBLIC_KEY
}

resource "aws_key_pair" "key_pair" {
  count      = 2
  key_name   = "${random_id.resource_prefix.hex}-public_key-${count.index}"
  public_key = tls_private_key.private_key[count.index].public_key_openssh
}

resource "tls_private_key" "private_key" {
  count     = 2
  algorithm = "RSA"
  rsa_bits  = 2048
}

data "template_file" "user-data-nginx" {
  count = 2
  template = file("${path.root}/scripts/web-server.tpl")
  vars = {
    "test_user_public_key" = var.PUBLIC_KEY
    "current_host_private_key" = jsonencode(tls_private_key.private_key[count.index].private_key_pem)
    "another_host_public_key" = tls_private_key.private_key[count.index].public_key_openssh
    "another_host_private_key" = jsonencode(tls_private_key.private_key[(count.index + 1) % 2].private_key_pem)
  }
}

resource "aws_instance" "ec2_instance" {
  count                  = 2
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  availability_zone      = var.ZONE
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.ssh_access.id]
  user_data              = data.template_file.user-data-nginx[count.index].rendered
  tags = {
    Name = "${random_id.resource_prefix.hex}-instance-${count.index}"
  }
}
