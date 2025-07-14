# Example showcasing the new AWS service security policies
# This demonstrates API Gateway, CloudTrail, ECR, ALB, and KMS configurations

# API Gateway REST API - Mixed security (some good, some issues)
resource "aws_api_gateway_rest_api" "example_api" {
  name        = "example-api"
  description = "Example API for testing"
  
  # Security issue: No minimum TLS version specified
  # minimum_tls_version = "TLS_1_2"  # Should be uncommented
  
  endpoint_configuration {
    types = ["EDGE"]
  }
}

# API Gateway stage with mixed configuration
resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example_api.id
  stage_name    = "prod"
  
  # Security issue: No access logging configured
  # access_log_settings {
  #   destination_arn = aws_cloudwatch_log_group.api_gateway.arn
  #   format = "standard"
  # }
  
  # Security issue: No throttling configured
  # throttle_settings {
  #   rate_limit  = 100
  #   burst_limit = 200
  # }
  
  # Good: X-Ray tracing enabled
  xray_tracing_enabled = true
}

# API Gateway method with authentication issue
resource "aws_api_gateway_method" "example_method" {
  rest_api_id   = aws_api_gateway_rest_api.example_api.id
  resource_id   = aws_api_gateway_rest_api.example_api.root_resource_id
  http_method   = "GET"
  
  # Security issue: No authentication
  authorization = "NONE"
}

resource "aws_api_gateway_deployment" "example" {
  depends_on = [aws_api_gateway_method.example_method]
  rest_api_id = aws_api_gateway_rest_api.example_api.id
}

# CloudTrail with security issues
resource "aws_cloudtrail" "example_trail" {
  name           = "example-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_bucket.id
  
  # Security issue: No KMS encryption
  # kms_key_id = aws_kms_key.cloudtrail_key.arn
  
  # Security issue: Not multi-region
  is_multi_region_trail = false
  
  # Security issue: Global service events disabled
  include_global_service_events = false
  
  # Security issue: Log file validation disabled
  enable_log_file_validation = false
  
  # Good: Logging is enabled (default)
  enable_logging = true
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "example-cloudtrail-logs-bucket"
  force_destroy = true
}

# ECR repository with security issues
resource "aws_ecr_repository" "app_repo" {
  name = "example-app"
  
  # Security issue: No image scanning
  # image_scanning_configuration {
  #   scan_on_push = true
  # }
  
  # Security issue: Mutable tags allowed
  image_tag_mutability = "MUTABLE"
  
  # Security issue: No encryption configured
  # encryption_configuration {
  #   encryption_type = "KMS"
  #   kms_key = aws_kms_key.ecr_key.arn
  # }
  
  # Security issue: Missing environment tag
  tags = {
    Name = "Example App Repository"
    # Environment = "production"  # Should be uncommented
  }
}

# Application Load Balancer with mixed configuration
resource "aws_lb" "example_alb" {
  name               = "example-prod-alb"
  internal           = false
  load_balancer_type = "application"
  
  # Good: Security groups configured
  security_groups = [aws_security_group.alb_sg.id]
  subnets        = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  
  # Security issue: No deletion protection for production ALB
  enable_deletion_protection = false
  
  # Security issue: Access logging disabled
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "test-alb"
    enabled = false
  }
  
  # Good: HTTP/2 enabled (default)
  enable_http2 = true
}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "example-alb-access-logs"
}

resource "aws_security_group" "alb_sg" {
  name_prefix = "alb-sg-"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ALB listener with HTTP without redirect
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.example_alb.arn
  port              = "80"
  protocol          = "HTTP"
  
  # Security issue: HTTP without redirect to HTTPS
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}

# ALB HTTPS listener with weak SSL policy
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.example_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  
  # Security issue: Weak SSL policy
  ssl_policy      = "ELBSecurityPolicy-2016-08"
  certificate_arn = aws_acm_certificate.example.arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}

resource "aws_lb_target_group" "example" {
  name     = "example-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  
  # Security issue: Health checks disabled
  health_check {
    enabled = false
  }
}

# KMS key with security issues
resource "aws_kms_key" "example_key" {
  # Security issue: No description
  # description = "Example KMS key for application encryption"
  
  # Security issue: Key rotation disabled
  enable_key_rotation = false
  
  # Security issue: Short deletion window
  deletion_window_in_days = 3
  
  # Security issue: Missing environment tag
  tags = {
    Name = "Example Key"
    # Environment = "production"  # Should be uncommented
  }
}

# KMS alias with naming issue
resource "aws_kms_alias" "example_alias" {
  # Security issue: Doesn't start with alias/
  name          = "example-key-alias"
  target_key_id = aws_kms_key.example_key.key_id
}

# Supporting resources for the examples
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public_1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "public_2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"
}

resource "aws_acm_certificate" "example" {
  domain_name       = "example.com"
  validation_method = "DNS"
}