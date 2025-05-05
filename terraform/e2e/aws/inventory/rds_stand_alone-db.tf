# DB Subnet Group
resource "aws_db_subnet_group" "standalone_rds_subnet_group" {
  name        = "${random_id.resource_prefix.hex}-standalone-rds-subnet-group"
  description = "Subnet group for standalone RDS instances"

  # Use the private subnet from network.tf
  subnet_ids = [
    aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id
  ]

  tags = {
    Name = "${random_id.resource_prefix.hex}-standalone-rds-subnet-group"
  }
}

# Security Group for RDS
resource "aws_security_group" "standalone_rds_sg" {
  name        = "${random_id.resource_prefix.hex}-standalone-rds-security-group"
  description = "Allow MySQL access to standalone RDS instance"
  vpc_id      = aws_vpc.fwaas_vpc.id  # Use VPC from network.tf

  ingress {
    from_port   = 3306                # MySQL default port
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]    # Allow access within the VPC
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]      # Allow all outbound traffic
  }

  tags = {
    Name = "${random_id.resource_prefix.hex}-standalone-rds-sg"
  }
}

# RDS Instance
resource "aws_db_instance" "standalone_rds_db_mysql_1" {
  allocated_storage    = 20
  max_allocated_storage = 30
  engine               = "mysql"
  engine_version       = "8.0.32"
  instance_class       = "db.t4g.micro"
  db_name              =  replace("${random_id.resource_prefix.hex}_standalone_database", "-", "_")
  username             = "admin"
  password             = "securepassword123"
  skip_final_snapshot  = true
  publicly_accessible  = false

  # Ensure the instance is in the correct VPC via subnet group and security group
  db_subnet_group_name    = aws_db_subnet_group.standalone_rds_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.standalone_rds_sg.id]

  tags = {
    Name = "${random_id.resource_prefix.hex}-standalone_rds_db_mysql_1"
  }
}
