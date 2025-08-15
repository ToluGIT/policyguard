# Variable definitions
variable "region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-west-2"
}

variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
  default     = "my-test-bucket"
}

variable "enable_encryption" {
  description = "Whether to enable encryption"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {
    Environment = "dev"
    Project     = "test"
  }
}

# Resource using variables
resource "aws_s3_bucket" "example" {
  bucket = var.bucket_name
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = var.enable_encryption ? "AES256" : null
      }
    }
  }
  
  tags = merge({
    Name = "${var.bucket_name}-${var.region}"
  }, var.tags)
}

resource "aws_dynamodb_table" "example" {
  name           = "${var.bucket_name}-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  
  attribute {
    name = "id"
    type = "S"
  }
  
  tags = var.tags
}