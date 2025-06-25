# Example of insecure S3 bucket configuration

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read-write"  # Security issue: publicly writable bucket

  tags = {
    Name        = "Insecure Bucket"
    Environment = "dev"
  }
}

resource "aws_s3_bucket" "no_encryption" {
  bucket = "my-unencrypted-bucket"
  
  # Security issue: no encryption at rest
  
  tags = {
    Name = "Unencrypted Bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.insecure_bucket.id

  # Security issue: public access not blocked
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "logging_disabled" {
  bucket = "my-bucket-without-logging"
  
  # Security issue: access logging disabled
  
  versioning {
    enabled = false  # Security issue: versioning disabled
  }
}