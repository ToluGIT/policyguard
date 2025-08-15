# Outputs for the security module

output "security_group_id" {
  description = "The ID of the security group"
  value       = aws_security_group.this.id
}

output "security_group_name" {
  description = "The name of the security group"
  value       = aws_security_group.this.name
}

output "security_group_arn" {
  description = "The ARN of the security group"
  value       = aws_security_group.this.arn
}