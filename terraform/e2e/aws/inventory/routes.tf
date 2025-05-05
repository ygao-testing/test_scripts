resource "aws_route_table" "bastion-subnet-rt" {
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-bastion-subnet-rt"
  }
}

resource "aws_route_table" "public-subnet-rt-before" {
  count = var.VPC_ENDPOINT == "" ? 1 : 0
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet-rt"
  }
}
resource "aws_route_table" "public-subnet-rt-2-before" {
  count = var.VPC_ENDPOINT == "" ? 1 : 0
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet-rt-2"
  }
}

resource "aws_route_table" "public-subnet-rt-after" {
  count = var.VPC_ENDPOINT == "" ? 0 : 1
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  route {
    cidr_block = aws_subnet.private_subnet.cidr_block
    vpc_endpoint_id = var.VPC_ENDPOINT == "" ? 0 : var.VPC_ENDPOINT
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet-rt"
  }
}
resource "aws_route_table" "public-subnet-rt-2-after" {
  count = var.VPC_ENDPOINT == "" ? 0 : 1
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  route {
    cidr_block = aws_subnet.private_subnet.cidr_block
    vpc_endpoint_id = var.VPC_ENDPOINT == "" ? 0 : var.VPC_ENDPOINT
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet-rt-2"
  }
}
resource "aws_route_table" "private-subnet-rt-before" {
  count = var.VPC_ENDPOINT == "" ? 1 : 0
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-private-subnet-rt"
  }

}

resource "aws_route_table" "private-subnet-rt-after" {
  count = var.VPC_ENDPOINT == "" ? 0 : 1
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    vpc_endpoint_id = var.VPC_ENDPOINT == "" ? 0 : var.VPC_ENDPOINT
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-private-subnet-rt"
  }
}

resource "aws_route_table" "endpoint-subnet-rt-after" {
  count = var.VPC_ENDPOINT == "" ? 0 : 1
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-endpoint-subnet-rt"
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = var.VPC_ENDPOINT == "" ? aws_route_table.private-subnet-rt-before[0].id : aws_route_table.private-subnet-rt-after[0].id
}

resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = var.VPC_ENDPOINT == "" ? aws_route_table.public-subnet-rt-before[0].id : aws_route_table.public-subnet-rt-after[0].id
}

resource "aws_route_table_association" "c" {
  count          = var.VPC_ENDPOINT == "" ? 0 : 1
  subnet_id      = aws_subnet.endpoint_subnet.id
  route_table_id = aws_route_table.endpoint-subnet-rt-after[0].id
}

resource "aws_route_table_association" "d" {
  subnet_id      = aws_subnet.bastion_subnet.id
  route_table_id = aws_route_table.bastion-subnet-rt.id
}
