output "instance_id_1" {
  value = aws_instance.ec2_instance[0].id
}

output "public_ip_1" {
  value = aws_instance.ec2_instance[0].public_ip
}

output "instance_id_2" {
  value = aws_instance.ec2_instance[1].id
}

output "public_ip_2" {
  value = aws_instance.ec2_instance[1].public_ip
}
