# Terraform configuration with security issues
# This example demonstrates common security mistakes

resource "aws_s3_bucket" "terraform_insecure_bucket" {
  bucket = "my-insecure-terraform-bucket"
  
  # SECURITY ISSUE: No encryption configured
  # SECURITY ISSUE: No versioning enabled
  # SECURITY ISSUE: No access logging
  
  tags = {
    Name        = "Insecure Terraform Bucket"
    ManagedBy   = "Terraform"
    Environment = "development"
  }
}

# SECURITY ISSUE: Public access not blocked
resource "aws_s3_bucket_acl" "terraform_insecure_bucket_acl" {
  bucket = aws_s3_bucket.terraform_insecure_bucket.id
  acl    = "public-read-write"  # SECURITY ISSUE: Public read-write access
}

resource "aws_instance" "terraform_insecure_instance" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  
  # SECURITY ISSUE: Public IP enabled
  associate_public_ip_address = true
  
  # SECURITY ISSUE: Unencrypted root volume
  root_block_device {
    encrypted = false
    volume_size = 20
  }
  
  # SECURITY ISSUE: IMDSv1 allowed
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # Should be "required"
  }
  
  tags = {
    Name      = "Insecure Terraform Instance"
    ManagedBy = "Terraform"
  }
}