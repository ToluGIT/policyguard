# Insecure Terraform configuration for testing

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read-write"  # VIOLATION: Public access
  
  # VIOLATION: No encryption
  # VIOLATION: No logging
  
  tags = {
    Name = "Public Bucket"
  }
}

resource "aws_instance" "public_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  associate_public_ip_address = true  # VIOLATION: Public IP
  
  root_block_device {
    encrypted = false  # VIOLATION: No encryption
  }
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # VIOLATION: IMDSv1 enabled
  }
  
  tags = {
    Name = "Public Instance"
  }
}

resource "aws_security_group" "open_sg" {
  name = "wide-open"
  
  # VIOLATION: SSH open to world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # VIOLATION: All ports open
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size              = 100
  encrypted         = false  # VIOLATION: No encryption
  
  tags = {
    Name = "Unencrypted Volume"
  }
}