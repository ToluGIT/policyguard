# Example Terraform module file

# This is a child module that creates an S3 bucket with standard security settings
resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  
  # Ensure encryption is enabled
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Set versioning
  versioning {
    enabled = var.enable_versioning
  }
  
  # Apply provided tags
  tags = merge(
    var.tags,
    {
      Name = var.bucket_name
      ManagedBy = "Terraform"
    }
  )
}

# Block public access
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Variables for the module
variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "enable_versioning" {
  description = "Whether to enable versioning for the S3 bucket"
  type        = bool
  default     = true
}

variable "tags" {
  description = "A map of tags to add to the bucket"
  type        = map(string)
  default     = {}
}

# Outputs from the module
output "bucket_id" {
  description = "The ID of the bucket"
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "The ARN of the bucket"
  value       = aws_s3_bucket.this.arn
}