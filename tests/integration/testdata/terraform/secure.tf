# Secure Terraform configuration for testing

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  logging {
    target_bucket = "my-log-bucket"
    target_prefix = "logs/"
  }
  
  versioning {
    enabled = true
  }
  
  tags = {
    Name        = "Secure Bucket"
    Environment = "production"
  }
}

resource "aws_instance" "secure_instance" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  associate_public_ip_address = false
  
  root_block_device {
    encrypted   = true
    volume_size = 20
  }
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }
  
  tags = {
    Name = "Secure Instance"
  }
}

resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Secure security group"
  
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
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