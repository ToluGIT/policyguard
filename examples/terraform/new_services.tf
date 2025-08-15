# Example showcasing the new AWS service security policies for v0.3.0
# This demonstrates SNS, SQS, and DynamoDB configurations with both secure and insecure patterns

###############################################################################
# SNS - Amazon Simple Notification Service
###############################################################################

# Insecure SNS topic - Missing encryption
resource "aws_sns_topic" "insecure_topic" {
  name = "insecure-topic"
  
  # Security issue: No server-side encryption
  # kms_master_key_id = aws_kms_key.sns_key.id
  
  # Security issue: No tags for resource management
  # tags = {
  #   Environment = "production"
  #   Owner       = "security-team"
  #   Purpose     = "notifications"
  # }
}

# SNS topic with public access policy
resource "aws_sns_topic_policy" "insecure_topic_policy" {
  arn = aws_sns_topic.insecure_topic.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Security issue: Public access allowed
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.insecure_topic.arn
        Effect    = "Allow"
      }
    ]
  })
}

# Insecure SNS FIFO topic - Missing deduplication
resource "aws_sns_topic" "insecure_fifo_topic" {
  name = "insecure-topic.fifo"
  fifo_topic = true
  
  # Security issue: Content-based deduplication disabled
  content_based_deduplication = false
  
  # Security issue: No encryption
  # kms_master_key_id = aws_kms_key.sns_key.id
}

# Insecure SNS subscription - Using HTTP
resource "aws_sns_topic_subscription" "insecure_http_subscription" {
  topic_arn = aws_sns_topic.insecure_topic.arn
  protocol  = "http" # Security issue: HTTP instead of HTTPS
  endpoint  = "http://example.com/webhook"
  
  # Security issue: No endpoint confirmation settings
  # endpoint_auto_confirms = true
  # confirmation_timeout_in_minutes = 5
}

# Secure SNS topic with proper encryption and settings
resource "aws_sns_topic" "secure_topic" {
  name = "secure-topic"
  
  # Good: Server-side encryption with KMS
  kms_master_key_id = aws_kms_key.sns_key.id
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "secure-notifications"
  }
}

# Secure SNS FIFO topic with proper configuration
resource "aws_sns_topic" "secure_fifo_topic" {
  name = "secure-topic.fifo"
  fifo_topic = true
  
  # Good: Content-based deduplication enabled
  content_based_deduplication = true
  
  # Good: Server-side encryption with KMS
  kms_master_key_id = aws_kms_key.sns_key.id
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "secure-notifications"
  }
}

# Secure SNS topic policy with proper access controls
resource "aws_sns_topic_policy" "secure_topic_policy" {
  arn = aws_sns_topic.secure_topic.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Good: Specific principal instead of public access
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/SNSPublisherRole"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.secure_topic.arn
        Effect    = "Allow"
      }
    ]
  })
}

# Secure SNS subscription using HTTPS
resource "aws_sns_topic_subscription" "secure_https_subscription" {
  topic_arn = aws_sns_topic.secure_topic.arn
  protocol  = "https" # Good: HTTPS for encryption in transit
  endpoint  = "https://example.com/secure-webhook"
  
  # Good: Endpoint confirmation settings
  endpoint_auto_confirms = true
  confirmation_timeout_in_minutes = 5
}

# Secure SQS subscription with raw delivery
resource "aws_sns_topic_subscription" "secure_sqs_subscription" {
  topic_arn = aws_sns_topic.secure_topic.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.secure_queue.arn
  
  # Good: Raw message delivery for better performance
  raw_message_delivery = true
}

###############################################################################
# SQS - Amazon Simple Queue Service
###############################################################################

# Insecure SQS queue - Missing encryption
resource "aws_sqs_queue" "insecure_queue" {
  name = "insecure-queue"
  
  # Security issue: No server-side encryption
  # kms_master_key_id = aws_kms_key.sqs_key.id
  sqs_managed_sse_enabled = false
  
  # Security issue: No tags for resource management
  # tags = {
  #   Environment = "production"
  #   Owner       = "security-team"
  #   Purpose     = "message-processing"
  # }
  
  # Security issue: No dead letter queue
  # redrive_policy = jsonencode({
  #   deadLetterTargetArn = aws_sqs_queue.dlq.arn
  #   maxReceiveCount     = 5
  # })
  
  # Security issue: Short message retention period (less than 1 day)
  message_retention_seconds = 3600 # 1 hour
}

# SQS queue with public access policy
resource "aws_sqs_queue_policy" "insecure_queue_policy" {
  queue_url = aws_sqs_queue.insecure_queue.url
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Security issue: Public access allowed
        Principal = "*"
        # Security issue: Overly permissive action
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.insecure_queue.arn
        Effect    = "Allow"
      }
    ]
  })
}

# Insecure SQS FIFO queue - Missing deduplication configuration
resource "aws_sqs_queue" "insecure_fifo_queue" {
  name = "insecure-queue.fifo"
  fifo_queue = true
  
  # Security issue: Content-based deduplication disabled without deduplication scope
  content_based_deduplication = false
  # deduplication_scope = "messageGroup"
  
  # Security issue: No encryption
  # kms_master_key_id = aws_kms_key.sqs_key.id
  sqs_managed_sse_enabled = false
}

# Secure SQS queue with proper configuration
resource "aws_sqs_queue" "secure_queue" {
  name = "secure-queue"
  
  # Good: Server-side encryption with KMS
  kms_master_key_id = aws_kms_key.sqs_key.id
  
  # Good: Dead letter queue configured
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 5
  })
  
  # Good: Reasonable message retention period (14 days)
  message_retention_seconds = 1209600
  
  # Good: Reasonable visibility timeout
  visibility_timeout_seconds = 300
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "secure-message-processing"
  }
}

# Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name = "dead-letter-queue"
  
  # Good: Server-side encryption with SQS-managed keys
  sqs_managed_sse_enabled = true
  
  # Good: Extended retention for failed messages
  message_retention_seconds = 1209600 # 14 days
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "failed-message-handling"
  }
}

# Secure SQS FIFO queue
resource "aws_sqs_queue" "secure_fifo_queue" {
  name = "secure-queue.fifo"
  fifo_queue = true
  
  # Good: Content-based deduplication enabled
  content_based_deduplication = true
  
  # Good: Server-side encryption with KMS
  kms_master_key_id = aws_kms_key.sqs_key.id
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "secure-message-processing"
  }
}

# Secure SQS queue policy with proper access controls
resource "aws_sqs_queue_policy" "secure_queue_policy" {
  queue_url = aws_sqs_queue.secure_queue.url
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Good: Specific principal instead of public access
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/SQSProcessorRole"
        }
        # Good: Specific actions instead of wildcard
        Action    = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage"
        ]
        Resource  = aws_sqs_queue.secure_queue.arn
        Effect    = "Allow"
      }
    ]
  })
}

###############################################################################
# DynamoDB - Amazon DynamoDB
###############################################################################

# Insecure DynamoDB table - Missing encryption and best practices
resource "aws_dynamodb_table" "insecure_table" {
  name           = "insecure-table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  
  # Security issue: No server-side encryption
  # server_side_encryption {
  #   enabled = true
  # }
  
  # Security issue: No point-in-time recovery
  # point_in_time_recovery {
  #   enabled = true
  # }
  
  # Security issue: No tags for resource management
  # tags = {
  #   Environment = "production"
  #   Owner       = "data-team"
  # }
  
  # Security issue: No auto scaling for provisioned capacity
  # (would need aws_appautoscaling_target and aws_appautoscaling_policy)
  
  attribute {
    name = "UserId"
    type = "S"
  }
  
  # Security issue: GSI with ALL projection type (potentially inefficient)
  global_secondary_index {
    name               = "UserIndex"
    hash_key           = "UserId"
    projection_type    = "ALL"
    read_capacity      = 10
    write_capacity     = 10
  }
}

# Insecure time-series DynamoDB table without TTL
resource "aws_dynamodb_table" "insecure_audit_log_table" {
  name           = "audit-logs"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LogId"
  range_key      = "Timestamp"
  
  # Security issue: No TTL for time-series data
  # ttl {
  #   attribute_name = "ExpirationTime"
  #   enabled        = true
  # }
  
  # Security issue: No server-side encryption
  # server_side_encryption {
  #   enabled = true
  # }
  
  attribute {
    name = "LogId"
    type = "S"
  }
  
  attribute {
    name = "Timestamp"
    type = "N"
  }
}

# Secure DynamoDB table with best practices
resource "aws_dynamodb_table" "secure_table" {
  name           = "secure-table"
  billing_mode   = "PAY_PER_REQUEST" # Good: Pay-per-request to avoid capacity planning
  hash_key       = "UserId"
  range_key      = "ItemId"
  
  # Good: Server-side encryption with customer-managed KMS key
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_key.arn
  }
  
  # Good: Point-in-time recovery enabled
  point_in_time_recovery {
    enabled = true
  }
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "data-team"
    Purpose     = "user-data-storage"
  }
  
  attribute {
    name = "UserId"
    type = "S"
  }
  
  attribute {
    name = "ItemId"
    type = "S"
  }
  
  attribute {
    name = "GSI1PK"
    type = "S"
  }
  
  # Good: GSI with INCLUDE projection type (more efficient)
  global_secondary_index {
    name               = "GSI1"
    hash_key           = "GSI1PK"
    projection_type    = "INCLUDE"
    non_key_attributes = ["UserName", "Email"]
  }
}

# Secure time-series DynamoDB table with TTL
resource "aws_dynamodb_table" "secure_metrics_table" {
  name           = "metrics-data"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "MetricId"
  range_key      = "Timestamp"
  
  # Good: TTL for time-series data
  ttl {
    attribute_name = "ExpirationTime"
    enabled        = true
  }
  
  # Good: Server-side encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_key.arn
  }
  
  # Good: Point-in-time recovery enabled
  point_in_time_recovery {
    enabled = true
  }
  
  # Good: Proper resource tags
  tags = {
    Environment = "production"
    Owner       = "metrics-team"
    Purpose     = "time-series-metrics"
  }
  
  attribute {
    name = "MetricId"
    type = "S"
  }
  
  attribute {
    name = "Timestamp"
    type = "N"
  }
  
  # Good: Stream enabled with correct view type for change tracking
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
}

# Lambda event source mapping for the DynamoDB stream
resource "aws_lambda_event_source_mapping" "metrics_stream_mapping" {
  event_source_arn  = aws_dynamodb_table.secure_metrics_table.stream_arn
  function_name     = "metrics-processor-function"
  starting_position = "LATEST"
  
  # Good: Proper batch size configuration
  batch_size = 100
  maximum_batching_window_in_seconds = 5
}

###############################################################################
# Shared KMS Keys
###############################################################################

# KMS key for SNS encryption
resource "aws_kms_key" "sns_key" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "SNS-KMS-Key"
    Environment = "production"
    Purpose = "SNS encryption"
  }
}

# KMS key for SQS encryption
resource "aws_kms_key" "sqs_key" {
  description             = "KMS key for SQS queue encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "SQS-KMS-Key"
    Environment = "production"
    Purpose = "SQS encryption"
  }
}

# KMS key for DynamoDB encryption
resource "aws_kms_key" "dynamodb_key" {
  description             = "KMS key for DynamoDB table encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "DynamoDB-KMS-Key"
    Environment = "production"
    Purpose = "DynamoDB encryption"
  }
}