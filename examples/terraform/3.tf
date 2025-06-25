# lambda-violations.tf
# This configuration will trigger multiple Lambda function policy violations

# Lambda with unencrypted environment variables (violation: lambda-env-vars-no-encryption)
resource "aws_lambda_function" "unencrypted_env" {
  function_name = "payment-processor"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "index.handler"
  runtime      = "python3.8"
  
  environment {
    variables = {
      DATABASE_URL = "postgresql://user:pass@host:5432/db"
      API_ENDPOINT = "https://api.example.com"
    }
  }
  # VIOLATION: Has environment variables but no kms_key_arn
}

# Lambda with sensitive data in env vars (violation: lambda-sensitive-env-vars)
resource "aws_lambda_function" "sensitive_env" {
  function_name = "user-authentication"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "auth.handler"
  runtime      = "nodejs18.x"
  kms_key_arn  = "arn:aws:kms:us-east-1:123456789012:key/12345678"
  
  environment {
    variables = {
      DB_PASSWORD = "supersecret123"  # VIOLATION: Password in env var
      API_SECRET  = "api-secret-key"   # VIOLATION: Secret in env var
      AUTH_TOKEN  = "bearer-token-123" # VIOLATION: Token in env var
    }
  }
}

# Production Lambda without VPC (violation: lambda-no-vpc)
resource "aws_lambda_function" "no_vpc_prod" {
  function_name = "production-api-handler"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "api.handler"
  runtime      = "python3.9"
  
  # VIOLATION: No vpc_config for production function
  
  tags = {
    Environment = "production"
  }
}

# Lambda with excessive timeout (violation: lambda-excessive-timeout)
resource "aws_lambda_function" "long_timeout" {
  function_name = "data-processor"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "process.handler"
  runtime      = "python3.9"
  timeout      = 900  # VIOLATION: 15 minutes (> 300 seconds)
}

# Lambda without X-Ray tracing (violation: lambda-no-xray)
resource "aws_lambda_function" "no_xray" {
  function_name = "order-service"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "orders.handler"
  runtime      = "nodejs18.x"
  # VIOLATION: No tracing_config
}

# Lambda with high concurrency (violation: lambda-high-concurrency)
resource "aws_lambda_function" "high_concurrency" {
  function_name = "bulk-processor"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "bulk.handler"
  runtime      = "python3.9"
  reserved_concurrent_executions = 2000  # VIOLATION: > 1000
}

# Lambda without DLQ (violation: lambda-no-dlq)
resource "aws_lambda_function" "no_dlq" {
  function_name = "event-handler"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "events.handler"
  runtime      = "python3.9"
  # VIOLATION: No dead_letter_config
}

# Lambda with deprecated runtime (violation: lambda-deprecated-runtime)
resource "aws_lambda_function" "old_runtime" {
  function_name = "legacy-function"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "legacy.handler"
  runtime      = "python3.6"  # VIOLATION: Deprecated runtime
}

# Lambda with unversioned layers (violation: lambda-layer-no-version)
resource "aws_lambda_function" "unversioned_layers" {
  function_name = "app-with-layers"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "app.handler"
  runtime      = "python3.9"
  
  layers = [
    "arn:aws:lambda:us-east-1:123456789012:layer:my-layer"  # VIOLATION: No version
  ]
}

# Lambda with public access (violation: lambda-public-access)
resource "aws_lambda_permission" "public_access" {
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "public-api"
  principal     = "*"  # VIOLATION: Public access
}

# Lambda with high privilege name (violation: lambda-high-privilege-name)
resource "aws_lambda_function" "admin_function" {
  function_name = "admin-super-privileged-function"  # VIOLATION: Contains "admin" and "privileged"
  role         = "arn:aws:iam::123456789012:role/lambda-admin-role"
  handler      = "admin.handler"
  runtime      = "python3.9"
}

# Lambda without log retention (violation: lambda-no-log-retention)
resource "aws_lambda_function" "no_log_retention" {
  function_name = "logging-function"
  role         = "arn:aws:iam::123456789012:role/lambda-role"
  handler      = "logs.handler"
  runtime      = "python3.9"
  # VIOLATION: Associated CloudWatch log group needs retention
}