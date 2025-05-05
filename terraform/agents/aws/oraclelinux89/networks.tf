# data "aws_ec2_managed_prefix_list" "fortinet_networks" {
#   filter {
#      name   = "prefix-list-name"
#      values = ["fortinet_networks"]
#   }
# }

resource "aws_vpc" "fwaas_vpc" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "${random_id.resource_prefix.hex}"
  }
}

resource "aws_vpc_dhcp_options" "dns_resolver" {
  domain_name_servers = ["1.1.1.1"]
}

resource "aws_vpc_dhcp_options_association" "dns_resolver" {
  vpc_id          = aws_vpc.fwaas_vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.dns_resolver.id
}

resource "aws_subnet" "bastion_subnet" {
  vpc_id                  = aws_vpc.fwaas_vpc.id
  cidr_block              = var.bastion_subnet
  map_public_ip_on_launch = true
  availability_zone       = local.available_zones[0]

  tags = {
    Name = "${random_id.resource_prefix.hex}-bastion-subnet"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.fwaas_vpc.id
  cidr_block              = var.public_subnets[0]
  map_public_ip_on_launch = true
  availability_zone       = local.available_zones[0]

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id             = aws_vpc.fwaas_vpc.id
  cidr_block         = var.private_subnets[0]
  availability_zone  = local.available_zones[0]

  tags = {
    Name = "${random_id.resource_prefix.hex}-private-subnet"
  }
}

resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.fwaas_vpc.id

  ingress {
    description     = "ssh"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    # prefix_list_ids = [data.aws_ec2_managed_prefix_list.fortinet_networks.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-bastion-sg"
  }
}

resource "aws_security_group" "web_server_sg" {
  name        = "web-server-sg"
  description = "Allow all traffic from private subnets and only SSH from public subnet"
  vpc_id      = aws_vpc.fwaas_vpc.id

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.bastion_subnet.cidr_block]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = aws_subnet.private_subnet[*].cidr_block
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-web-server-sg"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.fwaas_vpc.id

  tags = {
    Name = "${random_id.resource_prefix.hex}-igw"
  }
}
