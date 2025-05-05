resource "aws_vpc" "collector_vpc" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = random_id.resource_prefix.hex
  }
}

# data "aws_ec2_managed_prefix_list" "fortinet_networks" {
#   filter {
#      name   = "prefix-list-name"
#      values = ["fortinet_networks"]
#   }
# }

resource "aws_vpc_endpoint" "s3_private" {
  vpc_id            = aws_vpc.collector_vpc.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  route_table_ids   = [aws_route_table.public-rt.id]
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.collector_vpc.id
  cidr_block              = "10.1.10.0/24"
  map_public_ip_on_launch = true
  availability_zone       = var.ZONE

  tags = {
    Name = "${random_id.resource_prefix.hex}_public_subnet"
  }
}

resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.collector_vpc.id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    #prefix_list_ids = [data.aws_ec2_managed_prefix_list.fortinet_networks.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.collector_vpc.id

  tags = {
    Name = "${random_id.resource_prefix.hex}_igw"
  }
}
