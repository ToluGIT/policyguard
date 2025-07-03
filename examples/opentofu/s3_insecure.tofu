# OpenTofu configuration with security issues
# This example demonstrates common security mistakes

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-opentofu-bucket"
  
  # SECURITY ISSUE: No encryption configured
  # SECURITY ISSUE: No versioning enabled
  # SECURITY ISSUE: No access logging
  
  tags = {
    Name        = "Insecure OpenTofu Bucket"
    ManagedBy   = "OpenTofu"
    Environment = "development"
  }
}

# SECURITY ISSUE: Public access not blocked
resource "aws_s3_bucket_acl" "insecure_bucket_acl" {
  bucket = aws_s3_bucket.insecure_bucket.id
  acl    = "public-read-write"  # SECURITY ISSUE: Public read-write access
}

resource "aws_s3_bucket_policy" "insecure_bucket_policy" {
  bucket = aws_s3_bucket.insecure_bucket.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # SECURITY ISSUE: Allow access from anyone
        Action    = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.insecure_bucket.arn}/*"
      }
    ]
  })
}