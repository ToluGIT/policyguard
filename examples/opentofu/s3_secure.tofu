# OpenTofu configuration for secure S3 bucket
# This example demonstrates security best practices

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-opentofu-bucket"
  
  tags = {
    Name        = "Secure OpenTofu Bucket"
    ManagedBy   = "OpenTofu"
    Environment = "production"
  }
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure_bucket_logging" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "s3-access-logs/"
}

resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 10
  
  tags = {
    Name = "opentofu-s3-kms-key"
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-opentofu-log-bucket"
  
  tags = {
    Name      = "OpenTofu Log Bucket"
    ManagedBy = "OpenTofu"
  }
}