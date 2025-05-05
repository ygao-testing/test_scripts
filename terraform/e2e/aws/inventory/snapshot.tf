# Create a snapshot of the volume attached to web_server1
resource "aws_ebs_snapshot" "web_server1_snapshot" {
  volume_id   = aws_instance.web_server1.root_block_device[0].volume_id
  description = "snapshot of web_server1"

  tags = {
    Name  = "${random_id.resource_prefix.hex}-web_server1-snapshot"
    }
}

# Create a snapshot of the volume attached to web_server2
resource "aws_ebs_snapshot" "web_server2_snapshot" {
  volume_id   = aws_instance.web_server2.root_block_device[0].volume_id
  description = "snapshot of web_server2"

  tags = {
    Name  = "${random_id.resource_prefix.hex}-web_server2-snapshot"
    }
}
