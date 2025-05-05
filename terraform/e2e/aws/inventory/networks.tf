data "aws_ec2_managed_prefix_list" "fortinet_networks" {
  filter {
     name   = "prefix-list-name"
     values = ["fortinet_networks"]
  }
}

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

resource "aws_eip" "nat_gw_eip" {
  domain = "vpc"

  tags = {
    Name = "${random_id.resource_prefix.hex}-natgw"
  }

  depends_on = [aws_internet_gateway.gw]
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_gw_eip.id
  subnet_id     = aws_subnet.public_subnet.id

  tags = {
    Name = "${random_id.resource_prefix.hex}-natgw"
  }

  depends_on = [aws_internet_gateway.gw]
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
resource "aws_subnet" "private_subnet_2" {
  vpc_id             = aws_vpc.fwaas_vpc.id
  cidr_block         = var.private_subnets[1]
  availability_zone  = local.available_zones[1]

  tags = {
    Name = "${random_id.resource_prefix.hex}-private-subnet_2"
  }
}

resource "aws_subnet" "endpoint_subnet" {
  vpc_id             = aws_vpc.fwaas_vpc.id
  cidr_block         = var.endpoint_subnet
  availability_zone  = local.available_zones[0]

  tags = {
    Name = "${random_id.resource_prefix.hex}-endpoint-subnet"
    fortigatecnf_subnet_type = "endpoint"
  }
}

resource "aws_security_group" "bastion_sg" {
  name        = "${random_id.resource_prefix.hex}-bastion-sg"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.fwaas_vpc.id

  ingress {
    description     = "ssh"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.fortinet_networks.id]
  }
  ingress {
  description     = "Allow ICMP ping"
  from_port       = -1
  to_port         = -1
  protocol        = "icmp"
  prefix_list_ids = [data.aws_ec2_managed_prefix_list.fortinet_networks.id]  # Replace with the appropriate prefix list ID
  cidr_blocks = ["10.1.0.0/16"]
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
  name        = "${random_id.resource_prefix.hex}-web-server-sg"
  description = "Allow all traffic from private and endpoint subnets and only SSH from public subnet"
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

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [
      aws_subnet.endpoint_subnet.cidr_block
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "allow-ping-from-bastion-subnet" {
  name        = "${random_id.resource_prefix.hex}-allow-ping-from-bastion-subnet"
  description = "allow ping from base staion subnet"
  vpc_id      = aws_vpc.fwaas_vpc.id


  ingress {
    description = "allow icmp from bastion_subnet"
    from_port = -1
    to_port  =  -1
    protocol = "icmp"
    cidr_blocks = [aws_subnet.bastion_subnet.cidr_block]
  }


  tags = {
    Name = "${random_id.resource_prefix.hex}-allow-ping-from-bastion-subnet"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.fwaas_vpc.id

  tags = {
    Name = "${random_id.resource_prefix.hex}-igw"
  }
}
