package policyguard

import future.keywords.contains
import future.keywords.if

# Description: Security policies for AWS VPC resources (VPC, Subnets, Security Groups, NACLs)

# Deny VPC without flow logs enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_vpc"
    
    # Check if flow logs are not configured
    not resource.attributes.enable_flow_logs
    
    violation := {
        "id": sprintf("vpc-no-flow-logs-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-flow-logs-required",
        "severity": "high",
        "message": sprintf("VPC '%s' does not have flow logs enabled", [resource.name]),
        "details": "VPC Flow Logs provide visibility into network traffic and are essential for security monitoring",
        "remediation": "Create aws_flow_log resource for this VPC with appropriate configuration",
        "location": resource.location
    }
}

# Deny VPC with default security group allowing all traffic
deny[violation] {
    resource := input.resource
    resource.type == "aws_default_security_group"
    
    # Check if any ingress rules exist (default should have none)
    resource.attributes.ingress
    
    violation := {
        "id": sprintf("vpc-default-sg-has-rules-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-default-sg-no-rules",
        "severity": "high",
        "message": sprintf("Default security group '%s' has ingress rules defined", [resource.name]),
        "details": "Default security groups should not have any rules to prevent accidental exposure",
        "remediation": "Remove all ingress and egress rules from default security group",
        "location": resource.location
    }
}

# Deny subnets with auto-assign public IP enabled in production
deny[violation] {
    resource := input.resource
    resource.type == "aws_subnet"
    
    # Check if public IP auto-assignment is enabled
    resource.attributes.map_public_ip_on_launch == true
    
    # Check if it's a production subnet
    resource.attributes.tags.Environment == "production"
    
    violation := {
        "id": sprintf("vpc-subnet-auto-public-ip-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-subnet-no-auto-public-ip",
        "severity": "medium",
        "message": sprintf("Production subnet '%s' auto-assigns public IPs", [resource.name]),
        "details": "Production subnets should not automatically assign public IPs to instances",
        "remediation": "Set map_public_ip_on_launch = false and use NAT gateways for outbound traffic",
        "location": resource.location
    }
}

# Deny Network ACLs with allow all rules
deny[violation] {
    resource := input.resource
    resource.type == "aws_network_acl"
    
    # Check ingress rules
    rule := resource.attributes.ingress[_]
    rule.protocol == "-1"  # All protocols
    rule.cidr_block == "0.0.0.0/0"
    rule.action == "allow"
    
    violation := {
        "id": sprintf("vpc-nacl-allow-all-ingress-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-nacl-restrict-traffic",
        "severity": "high",
        "message": sprintf("Network ACL '%s' allows all ingress traffic", [resource.name]),
        "details": "Network ACLs should have specific rules, not allow all traffic",
        "remediation": "Define specific rules for allowed traffic patterns",
        "location": resource.location
    }
}

# Deny VPC endpoints without private DNS enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_vpc_endpoint"
    
    # Check if private DNS is disabled
    resource.attributes.private_dns_enabled == false
    
    # Only relevant for Interface endpoints
    resource.attributes.vpc_endpoint_type == "Interface"
    
    violation := {
        "id": sprintf("vpc-endpoint-no-private-dns-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-endpoint-private-dns",
        "severity": "medium",
        "message": sprintf("VPC endpoint '%s' does not have private DNS enabled", [resource.name]),
        "details": "Interface endpoints should have private DNS enabled for seamless service integration",
        "remediation": "Set private_dns_enabled = true",
        "location": resource.location
    }
}

# Deny VPC peering connections without DNS resolution
deny[violation] {
    resource := input.resource
    resource.type == "aws_vpc_peering_connection_options"
    
    # Check if DNS resolution is disabled
    not resource.attributes.accepter.allow_remote_vpc_dns_resolution
    
    violation := {
        "id": sprintf("vpc-peering-no-dns-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-peering-dns-resolution",
        "severity": "low",
        "message": sprintf("VPC peering connection '%s' does not allow DNS resolution", [resource.name]),
        "details": "VPC peering connections should allow DNS resolution for better connectivity",
        "remediation": "Enable allow_remote_vpc_dns_resolution for both accepter and requester",
        "location": resource.location
    }
}

# Deny VPN connections without redundancy
deny[violation] {
    resource := input.resource
    resource.type == "aws_vpn_connection"
    
    # Check if static routes only (no redundancy)
    resource.attributes.static_routes_only == true
    
    violation := {
        "id": sprintf("vpc-vpn-no-redundancy-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-vpn-redundancy",
        "severity": "medium",
        "message": sprintf("VPN connection '%s' uses static routes only (no redundancy)", [resource.name]),
        "details": "VPN connections should use BGP for automatic failover and redundancy",
        "remediation": "Set static_routes_only = false and configure BGP",
        "location": resource.location
    }
}

# Deny Internet Gateway in production without proper controls
deny[violation] {
    resource := input.resource
    resource.type == "aws_internet_gateway"
    
    # Check if attached to production VPC
    resource.attributes.tags.Environment == "production"
    
    violation := {
        "id": sprintf("vpc-igw-in-production-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-igw-controls",
        "severity": "medium",
        "message": sprintf("Internet Gateway '%s' attached to production VPC", [resource.name]),
        "details": "Production VPCs with IGW should have strict security controls and monitoring",
        "remediation": "Ensure proper security groups, NACLs, and monitoring are in place",
        "location": resource.location
    }
}

# Deny route tables with unrestricted routes to IGW
deny[violation] {
    resource := input.resource
    resource.type == "aws_route"
    
    # Check for routes to IGW with broad CIDR
    resource.attributes.destination_cidr_block == "0.0.0.0/0"
    resource.attributes.gateway_id
    contains(resource.attributes.gateway_id, "igw-")
    
    violation := {
        "id": sprintf("vpc-route-unrestricted-igw-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-route-restrictions",
        "severity": "medium",
        "message": sprintf("Route table has unrestricted route to Internet Gateway", []),
        "details": "Routes to Internet Gateway should be carefully controlled",
        "remediation": "Ensure this route is necessary and properly secured with NACLs and security groups",
        "location": resource.location
    }
}

# Deny NAT Gateways without multi-AZ setup for production
deny[violation] {
    resource := input.resource
    resource.type == "aws_nat_gateway"
    
    # Check if it's for production
    resource.attributes.tags.Environment == "production"
    
    # This is a simplified check - in practice, you'd check for multiple NAT gateways
    
    violation := {
        "id": sprintf("vpc-nat-no-multi-az-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-nat-multi-az",
        "severity": "medium",
        "message": sprintf("Production NAT Gateway '%s' should have multi-AZ redundancy", [resource.name]),
        "details": "Production environments should have NAT Gateways in multiple AZs for high availability",
        "remediation": "Deploy NAT Gateways in multiple availability zones",
        "location": resource.location
    }
}

# Deny VPC without DNS hostnames enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_vpc"
    
    # Check if DNS hostnames are disabled
    resource.attributes.enable_dns_hostnames == false
    
    violation := {
        "id": sprintf("vpc-no-dns-hostnames-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-dns-hostnames",
        "severity": "low",
        "message": sprintf("VPC '%s' does not have DNS hostnames enabled", [resource.name]),
        "details": "DNS hostnames should be enabled for better instance identification",
        "remediation": "Set enable_dns_hostnames = true",
        "location": resource.location
    }
}

# Deny VPC Flow Logs without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_flow_log"
    
    # Check if encryption is not configured
    not resource.attributes.encrypt_at_rest
    
    violation := {
        "id": sprintf("vpc-flow-logs-no-encryption-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "vpc-flow-logs-encryption",
        "severity": "medium",
        "message": sprintf("VPC Flow Logs '%s' are not encrypted", [resource.name]),
        "details": "Flow logs should be encrypted at rest for security",
        "remediation": "Enable encryption for flow logs using KMS",
        "location": resource.location
    }
}