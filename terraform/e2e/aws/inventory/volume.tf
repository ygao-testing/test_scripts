
# First EBS Volume: General Purpose SSD (gp3)
resource "aws_ebs_volume" "volume1" {
  availability_zone = local.available_zones[0]  # Specify the availability zone
  size              = 1
  type       = "gp3"                     # Volume type: General Purpose SSD (gp3)

  tags = {
    Name = "${random_id.resource_prefix.hex}-volume1"
  }
}

# Second EBS Volume: Cold HDD (sc1)
resource "aws_ebs_volume" "volume2" {
  availability_zone = local.available_zones[0]  # Specify the availability zone
  size              = 128
  type       = "sc1"                     # Volume type: Cold HDD

  tags = {
    Name = "${random_id.resource_prefix.hex}-volume2"
  }
}
