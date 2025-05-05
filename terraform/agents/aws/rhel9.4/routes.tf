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

resource "aws_route_table" "public-subnet-rt" {
  vpc_id = aws_vpc.fwaas_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-public-subnet-rt"
  }
}



resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public-subnet-rt.id
}

resource "aws_route_table_association" "d" {
  subnet_id      = aws_subnet.bastion_subnet.id
  route_table_id = aws_route_table.bastion-subnet-rt.id
}
