# WARNING: This configuration is intentionally insecure for educational purposes
# DO NOT use this in any real environment

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-public-bucket"
}

# Disabling all public access blocks (INSECURE)
resource "aws_s3_bucket_public_access_block" "insecure_access" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Making bucket publicly readable (INSECURE)
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.insecure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.insecure_bucket.arn}/*"
      }
    ]
  })
}

# Weak encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "weak_encryption" {
  bucket = aws_s3_bucket.insecure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # Using S3-managed keys instead of KMS
    }
  }
}

# No versioning (INSECURE - no protection against deletions)
resource "aws_s3_bucket_versioning" "no_versioning" {
  bucket = aws_s3_bucket.insecure_bucket.id
  
  versioning_configuration {
    status = "Disabled"
  }
}

# No logging (INSECURE - no audit trail)
# Logging is simply not configured