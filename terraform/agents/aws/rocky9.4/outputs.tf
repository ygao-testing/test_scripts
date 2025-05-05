output "agent_host_instance_id" {
  value = aws_instance.rocky.id
}

output "agent_host_private_ip" {
  value = aws_instance.rocky.private_ip
}

output "agent_host_public_ip" {
  value = aws_instance.rocky.public_ip
}

output "agent_ami_id" {
  value = data.aws_ami.rocky.id
}

output "agent_subnet_id" {
  value = aws_subnet.public_subnet.id
}

output "agent_vpc_id" {
  value = aws_vpc.fwaas_vpc.id
}

output "region" {
  value = var.REGION
}
