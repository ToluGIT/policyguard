package policyguard

import future.keywords.contains
import future.keywords.if

# Deny EC2 instances with public IP addresses
deny[violation] {
    resource := input.resource
    resource.type == "aws_instance"
    
    resource.attributes.associate_public_ip_address == true
    
    violation := {
        "id": sprintf("ec2-public-ip-%s", [resource.name]),
        "policy_id": "ec2_instance_public_ip",
        "severity": "medium",
        "message": sprintf("EC2 instance '%s' has a public IP address", [resource.name]),
        "details": "EC2 instances should not have public IP addresses unless explicitly required",
        "remediation": "Set associate_public_ip_address to false and use NAT gateways or VPN for external access"
    }
}

# Deny EC2 instances without encrypted root volumes
deny[violation] {
    resource := input.resource
    resource.type == "aws_instance"
    
    resource.attributes.root_block_device.encrypted == false
    
    violation := {
        "id": sprintf("ec2-unencrypted-root-%s", [resource.name]),
        "policy_id": "ec2_instance_encryption",
        "severity": "high",
        "message": sprintf("EC2 instance '%s' has unencrypted root volume", [resource.name]),
        "details": "EC2 instance root volumes should be encrypted to protect data at rest",
        "remediation": "Set root_block_device.encrypted to true"
    }
}

# Deny EC2 instances without IMDSv2 enforced
deny[violation] {
    resource := input.resource
    resource.type == "aws_instance"
    
    resource.attributes.metadata_options.http_tokens != "required"
    
    violation := {
        "id": sprintf("ec2-imdsv1-%s", [resource.name]),
        "policy_id": "ec2_instance_imdsv2",
        "severity": "high",
        "message": sprintf("EC2 instance '%s' does not enforce IMDSv2", [resource.name]),
        "details": "IMDSv2 should be enforced to prevent SSRF attacks",
        "remediation": "Set metadata_options.http_tokens to 'required'"
    }
}

# Deny security groups with unrestricted inbound access
deny[violation] {
    resource := input.resource
    resource.type == "aws_security_group"
    
    rule := resource.attributes.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port == 0
    rule.to_port == 0
    
    violation := {
        "id": sprintf("sg-unrestricted-all-%s", [resource.name]),
        "policy_id": "security_group_unrestricted",
        "severity": "critical",
        "message": sprintf("Security group '%s' allows unrestricted inbound access", [resource.name]),
        "details": "Security groups should not allow unrestricted access from 0.0.0.0/0",
        "remediation": "Restrict ingress rules to specific ports and source IP ranges"
    }
}

# Deny security groups with SSH open to the world
deny[violation] {
    resource := input.resource
    resource.type == "aws_security_group"
    
    rule := resource.attributes.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port <= 22
    rule.to_port >= 22
    rule.protocol == "tcp"
    
    violation := {
        "id": sprintf("sg-ssh-open-%s", [resource.name]),
        "policy_id": "security_group_ssh_open",
        "severity": "critical",
        "message": sprintf("Security group '%s' allows SSH access from anywhere", [resource.name]),
        "details": "SSH (port 22) should not be open to 0.0.0.0/0",
        "remediation": "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager"
    }
}

# Deny security groups with SSH open to the world (all protocols)
deny[violation] {
    resource := input.resource
    resource.type == "aws_security_group"
    
    rule := resource.attributes.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.protocol == "-1"
    
    violation := {
        "id": sprintf("sg-ssh-open-all-%s", [resource.name]),
        "policy_id": "security_group_ssh_open",
        "severity": "critical",
        "message": sprintf("Security group '%s' allows all traffic including SSH from anywhere", [resource.name]),
        "details": "Security group allows all protocols from 0.0.0.0/0, including SSH",
        "remediation": "Restrict access to specific protocols and IP ranges"
    }
}

# Deny unencrypted EBS volumes
deny[violation] {
    resource := input.resource
    resource.type == "aws_ebs_volume"
    
    resource.attributes.encrypted == false
    
    violation := {
        "id": sprintf("ebs-unencrypted-%s", [resource.name]),
        "policy_id": "ebs_volume_encryption",
        "severity": "high",
        "message": sprintf("EBS volume '%s' is not encrypted", [resource.name]),
        "details": "EBS volumes should be encrypted to protect data at rest",
        "remediation": "Set encrypted to true and optionally specify a KMS key"
    }
}