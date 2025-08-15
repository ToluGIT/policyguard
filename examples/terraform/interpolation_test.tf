variable "enable_encryption" {
  description = "Whether to enable encryption for resources"
  type        = bool
  default     = true
}

variable "encryption_key" {
  description = "KMS key ID to use for encryption"
  type        = string
  default     = "aws/s3"
}

variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
  default     = "secure-bucket"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

# Test variable usage in simple attribute assignment
resource "aws_s3_bucket" "test_bucket" {
  bucket = var.bucket_name
  
  # Test string interpolation with variables
  bucket_prefix = "${var.environment}-${var.bucket_name}-logs"
  
  # Test conditional expression
  force_destroy = var.environment == "dev" ? true : false
  
  # Test nested blocks with variables
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # Test conditional with variable
        sse_algorithm = var.enable_encryption ? "AES256" : null
        
        # Test conditional with variable referencing another variable
        kms_master_key_id = var.enable_encryption ? var.encryption_key : null
      }
    }
  }
  
  # Test variable in map construction
  tags = {
    Name        = var.bucket_name
    Environment = var.environment
    Encrypted   = var.enable_encryption ? "yes" : "no"
    ManagedBy   = "PolicyGuard"
  }
}

# Test variable usage in numeric context
resource "aws_cloudwatch_log_group" "test_logs" {
  name = "/aws/s3/${var.bucket_name}"
  
  # Test numeric variable
  retention_in_days = var.log_retention_days
  
  # Test binary operation with variable
  kms_key_id = var.enable_encryption ? var.encryption_key : null
  
  # Test binary operation with numeric variable
  tags = {
    RetentionDays = "${var.log_retention_days + 1} days"
    Environment   = var.environment
  }
}