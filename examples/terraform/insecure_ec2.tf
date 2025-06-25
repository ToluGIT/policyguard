# Example of insecure EC2 configuration

resource "aws_instance" "insecure_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # Security issue: instance has public IP
  associate_public_ip_address = true
  
  # Security issue: no encryption for root volume
  root_block_device {
    encrypted = false
  }
  
  # Security issue: IMDSv1 is enabled (should use IMDSv2)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  # Should be "required" for IMDSv2
    http_put_response_hop_limit = 1
  }
  
  tags = {
    Name = "Insecure Instance"
  }
}

resource "aws_security_group" "wide_open" {
  name        = "allow_all"
  description = "Allow all inbound traffic"
  
  # Security issue: allows all traffic from anywhere
  ingress {
    description = "All traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Security issue: allows all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ssh_open" {
  name = "ssh_from_anywhere"
  
  # Security issue: SSH open to the world
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size              = 40
  
  # Security issue: EBS volume not encrypted
  encrypted = false
  
  tags = {
    Name = "Unencrypted Volume"
  }
}