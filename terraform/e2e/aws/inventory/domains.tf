data "aws_region" "current" {}

data "template_file" "user-data-nginx" {
  template = file("${path.root}/scripts/web-server.tpl")
  vars = {
    "bastion_public_key"   = tls_private_key.bastion_keypair.public_key_openssh
    "test_user_public_key" = var.PUBLIC_KEY
  }
}

data "template_file" "user-data-bastion" {
  template = file("${path.root}/scripts/amazon-linux-bastion.tpl")
  vars = {
    "private_key" = jsonencode(tls_private_key.bastion_keypair.private_key_openssh)
    "public_key" = tls_private_key.bastion_keypair.public_key_openssh
    "test_user_public_key" = var.PUBLIC_KEY
  }
}

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

  owners = ["099720109477"] # Canonical
}

data "aws_ami" "amazon-linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
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

resource "aws_instance" "web_server1" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  availability_zone      = local.available_zones[0]
  user_data              = data.template_file.user-data-nginx.rendered
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.web_server_sg.id,aws_security_group.allow-ping-from-bastion-subnet.id]
  private_ip             = "10.1.81.188"  # Static private IP address

  tags = {
    Name = "${random_id.resource_prefix.hex}-web_server1"
  }

  depends_on = [
    aws_nat_gateway.nat_gw
  ]
}
resource "aws_instance" "web_server2" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  availability_zone      = local.available_zones[0]
  user_data              = data.template_file.user-data-nginx.rendered
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.web_server_sg.id]
  private_ip             = "10.1.81.189"  # Static private IP address

  tags = {
    Name = "${random_id.resource_prefix.hex}-web_server2"
  }

  depends_on = [
    aws_nat_gateway.nat_gw
  ]
}


resource "aws_instance" "bastion" {
  ami                    = data.aws_ami.amazon-linux.id
  instance_type          = "t2.micro"
  availability_zone      = local.available_zones[0]
  user_data              = data.template_file.user-data-bastion.rendered
  subnet_id              = aws_subnet.bastion_subnet.id
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-bastion"
  }
}
