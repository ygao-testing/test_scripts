resource "aws_network_interface" "bastion_subnet_interface" {
  subnet_id       = aws_subnet.bastion_subnet.id      # Network interface in Bastion subnet
  security_groups = [aws_security_group.bastion_sg.id]  # Security group for Bastion subnet

  tags = {
    Name = "${random_id.resource_prefix.hex}-bastion-subnet-interface"  # More generic name
  }
}

resource "aws_network_interface" "private_subnet_interface" {
  subnet_id       = aws_subnet.private_subnet.id      # Network interface in Private subnet

  tags = {
    Name = "${random_id.resource_prefix.hex}-private-subnet-interface"  # More generic name
  }
}
