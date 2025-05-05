data "aws_region" "current" {}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
      name   = "name"
      values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
      name   = "virtualization-type"
      values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "ubuntu" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  availability_zone      = local.available_zones[0]
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-ubuntu2004"
  }
}

resource "aws_s3_bucket" "s3_bucket" {
  bucket = "${lower(random_id.resource_prefix.hex)}-s3"
  acl    = "private"
}
