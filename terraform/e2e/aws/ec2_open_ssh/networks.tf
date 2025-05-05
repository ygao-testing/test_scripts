resource "aws_vpc" "vpc" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "${random_id.resource_prefix.hex}"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.public_subnet
  map_public_ip_on_launch = true
  availability_zone       = var.ZONE

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet"
  }
}

resource "aws_security_group" "public_access_ssh" {
  vpc_id      = aws_vpc.vpc.id
  name        = "allow_all"
  description = "Allow access from anywhere through SSH"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-sg"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${random_id.resource_prefix.hex}-igw"
  }
}
