# ec2-violations.tf
# This configuration will trigger multiple EC2 and Security Group policy violations

# EC2 instance with public IP (violation: ec2-public-ip)
resource "aws_instance" "public_instance" {
  name                    = "public-web-server"
  ami                     = "ami-0abcdef1234567890"
  instance_type           = "t3.micro"
  associate_public_ip_address = true  # VIOLATION: Public IP address
  
  # Unencrypted root volume (violation: ec2-unencrypted-root)
  root_block_device {
    encrypted = false  # VIOLATION: Unencrypted root volume
    volume_size = 20
  }
  
  # IMDSv1 allowed (violation: ec2-imdsv1)
  metadata_options {
    http_tokens = "optional"  # VIOLATION: Should be "required" for IMDSv2
    http_endpoint = "enabled"
  }
}

# Security group with unrestricted access (violation: sg-unrestricted-all)
resource "aws_security_group" "unrestricted" {
  name        = "completely-open-sg"
  description = "Security group with unrestricted access"
  
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"  # All protocols
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Unrestricted access
  }
}

# Security group with SSH open to world (violation: sg-ssh-open)
resource "aws_security_group" "ssh_open" {
  name        = "ssh-open-to-world"
  description = "Security group with SSH open"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: SSH open to world
  }
}

# Another security group with all protocols allowed (violation: sg-ssh-open-all)
resource "aws_security_group" "all_protocols_open" {
  name        = "all-protocols-allowed"
  description = "Security group allowing all protocols"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"  # All protocols
    cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: All protocols from anywhere
  }
}

# Unencrypted EBS volume (violation: ebs-unencrypted)
resource "aws_ebs_volume" "unencrypted_volume" {
  name              = "data-volume-unencrypted"
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # VIOLATION: Unencrypted EBS volume
}