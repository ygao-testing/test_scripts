output "agent_host_instance_id" {
  value = aws_instance.agent_host.id
}

output "agent_host_private_ip" {
  value = aws_instance.agent_host.private_ip
}

output "agent_host_public_ip" {
  value = aws_instance.agent_host.public_ip
}

output "agent_ami_id" {
  value = data.aws_ami.host_ami.id
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
