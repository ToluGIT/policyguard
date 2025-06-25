# vpc-violations.tf
# This configuration will trigger multiple VPC and network policy violations

# VPC without flow logs (violation: vpc-no-flow-logs)
resource "aws_vpc" "no_flow_logs" {
  cidr_block = "10.0.0.0/16"
  
  # VIOLATION: No flow logs enabled (would need separate aws_flow_log resource)
  
  tags = {
    Name = "insecure-vpc"
  }
}

# Default security group with ingress rules (violation: vpc-default-sg-has-rules)
resource "aws_default_security_group" "with_rules" {
  vpc_id = aws_vpc.no_flow_logs.id
  
  # VIOLATION: Default security group should have no rules
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Production subnet with auto-assign public IP (violation: vpc-subnet-auto-public-ip)
resource "aws_subnet" "prod_public_auto_assign" {
  vpc_id                  = aws_vpc.no_flow_logs.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true  # VIOLATION: Auto-assigns public IPs
  
  tags = {
    Name        = "prod-public-subnet"
    Environment = "production"
  }
}

# Network ACL with allow all rules (violation: vpc-nacl-allow-all-ingress)
resource "aws_network_acl" "allow_all" {
  vpc_id = aws_vpc.no_flow_logs.id
  
  # VIOLATION: Allows all ingress traffic
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

# VPC endpoint without private DNS (violation: vpc-endpoint-no-private-dns)
resource "aws_vpc_endpoint" "no_private_dns" {
  vpc_id              = aws_vpc.no_flow_logs.id
  service_name        = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = false  # VIOLATION: Private DNS disabled
  
  subnet_ids = [aws_subnet.prod_public_auto_assign.id]
}

# VPC peering without DNS resolution (violation: vpc-peering-no-dns)
resource "aws_vpc_peering_connection_options" "no_dns" {
  vpc_peering_connection_id = "pcx-12345678"
  
  accepter {
    allow_remote_vpc_dns_resolution = false  # VIOLATION: DNS resolution disabled
  }
}

# VPN connection without redundancy (violation: vpc-vpn-no-redundancy)
resource "aws_vpn_connection" "static_only" {
  customer_gateway_id = "cgw-12345678"
  type               = "ipsec.1"
  static_routes_only = true  # VIOLATION: No BGP redundancy
  vpn_gateway_id     = "vgw-12345678"
}

# Internet Gateway in production (violation: vpc-igw-in-production)
resource "aws_internet_gateway" "prod_igw" {
  vpc_id = aws_vpc.no_flow_logs.id
  
  tags = {
    Name        = "production-igw"
    Environment = "production"  # VIOLATION: IGW in production VPC
  }
}

# Route to IGW (violation: vpc-route-unrestricted-igw)
resource "aws_route" "unrestricted_igw" {
  route_table_id         = "rtb-12345678"
  destination_cidr_block = "0.0.0.0/0"  # VIOLATION: Unrestricted route
  gateway_id             = "igw-12345678"  # To Internet Gateway
}

# NAT Gateway for production (violation: vpc-nat-no-multi-az)
resource "aws_nat_gateway" "prod_single_az" {
  allocation_id = "eipalloc-12345678"
  subnet_id     = aws_subnet.prod_public_auto_assign.id
  
  tags = {
    Name        = "production-nat"
    Environment = "production"  # VIOLATION: Single NAT for production
  }
}

# VPC without DNS hostnames (violation: vpc-no-dns-hostnames)
resource "aws_vpc" "no_dns_hostnames" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = false  # VIOLATION: DNS hostnames disabled
  
  tags = {
    Name = "vpc-without-dns-hostnames"
  }
}

# Flow logs without encryption (violation: vpc-flow-logs-no-encryption)
resource "aws_flow_log" "unencrypted_logs" {
  iam_role_arn    = "arn:aws:iam::123456789012:role/flow-logs-role"
  log_destination = "arn:aws:logs:us-east-1:123456789012:log-group:vpc-flow-logs"
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.no_flow_logs.id
  
  # VIOLATION: No encryption configured (encrypt_at_rest not set)
}

# Another VPC missing flow logs attribute
resource "aws_vpc" "missing_flow_logs_attr" {
  cidr_block = "10.2.0.0/16"
  
  enable_flow_logs = false  # VIOLATION: Flow logs explicitly disabled
  
  tags = {
    Name = "vpc-flow-logs-disabled"
  }
}