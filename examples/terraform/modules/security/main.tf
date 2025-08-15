# Security module for creating secure AWS security groups

resource "aws_security_group" "this" {
  name        = var.name
  description = var.description
  vpc_id      = var.vpc_id
  
  # Add tags
  tags = merge(
    var.tags,
    {
      Name = var.name
      ManagedBy = "Terraform"
    }
  )
}

# Create ingress rules
resource "aws_security_group_rule" "ingress" {
  count = length(var.ingress_rules)
  
  security_group_id = aws_security_group.this.id
  type              = "ingress"
  from_port         = var.ingress_rules[count.index].from_port
  to_port           = var.ingress_rules[count.index].to_port
  protocol          = var.ingress_rules[count.index].protocol
  cidr_blocks       = var.ingress_rules[count.index].cidr_blocks
  description       = lookup(var.ingress_rules[count.index], "description", null)
}

# Create egress rules
resource "aws_security_group_rule" "egress" {
  count = length(var.egress_rules)
  
  security_group_id = aws_security_group.this.id
  type              = "egress"
  from_port         = var.egress_rules[count.index].from_port
  to_port           = var.egress_rules[count.index].to_port
  protocol          = var.egress_rules[count.index].protocol
  cidr_blocks       = var.egress_rules[count.index].cidr_blocks
  description       = lookup(var.egress_rules[count.index], "description", null)
}