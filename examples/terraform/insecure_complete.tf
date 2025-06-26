# example of various AWS resources with security issues

# Insecure S3 bucket
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-sensitive-data"
  acl    = "public-read"  # VIOLATION: Public access
  
  # VIOLATION: No encryption
  # VIOLATION: No logging
  # VIOLATION: No versioning
}

# Insecure RDS instance
resource "aws_db_instance" "main_database" {
  identifier     = "prod-database"
  engine         = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.medium"
  
  allocated_storage = 100
  storage_encrypted = false  # VIOLATION: No encryption
  
  db_name  = "myapp"
  username = "admin"  # VIOLATION: Default username
  password = "changeme123!"  # VIOLATION: Hardcoded password
  
  publicly_accessible    = true  # VIOLATION: Public access
  backup_retention_period = 1    # VIOLATION: Short backup retention
  deletion_protection    = false # VIOLATION: No deletion protection
  
  skip_final_snapshot = true
  
  tags = {
    Environment = "production"
  }
}

# Insecure IAM policy
resource "aws_iam_policy" "too_permissive" {
  name = "admin-everything"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"      # VIOLATION: Wildcard actions
        Resource = "*"      # VIOLATION: Wildcard resources
      }
    ]
  })
}

# Insecure IAM role
resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Insecure Lambda function
resource "aws_lambda_function" "process_data" {
  filename         = "lambda.zip"
  function_name    = "process-sensitive-data"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.handler"
  source_code_hash = "dummy"
  
  runtime = "python2.7"  # VIOLATION: Deprecated runtime
  timeout = 900          # VIOLATION: Excessive timeout
  
  environment {
    variables = {
      DATABASE_PASSWORD = "secretpass123"  # VIOLATION: Sensitive data in env vars
      API_SECRET_KEY    = "sk_live_abcd"   # VIOLATION: Sensitive data in env vars
    }
  }
  
  # VIOLATION: No KMS key for environment variables
  # VIOLATION: No VPC configuration
  # VIOLATION: No dead letter queue
  # VIOLATION: No X-Ray tracing
}

# Insecure VPC
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  enable_dns_hostnames = false  # VIOLATION: DNS hostnames disabled
  
  # VIOLATION: No flow logs
  
  tags = {
    Name = "main-vpc"
  }
}

# Insecure subnet
resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  
  map_public_ip_on_launch = true  # VIOLATION: Auto-assign public IPs
  
  tags = {
    Name        = "public-subnet"
    Environment = "production"
  }
}

# Insecure security group
resource "aws_security_group" "wide_open" {
  name        = "allow-everything"
  description = "Allow all traffic"
  vpc_id      = aws_vpc.main.id
  
  # VIOLATION: Unrestricted ingress
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # VIOLATION: SSH open to world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Insecure Network ACL
resource "aws_network_acl" "bad_nacl" {
  vpc_id = aws_vpc.main.id
  
  # VIOLATION: Allow all traffic
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

# Insecure EC2 instance
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  associate_public_ip_address = true  # VIOLATION: Public IP
  
  vpc_security_group_ids = [aws_security_group.wide_open.id]
  
  root_block_device {
    encrypted = false  # VIOLATION: No encryption
  }
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # VIOLATION: IMDSv1 enabled
  }
  
  tags = {
    Name = "web-server"
  }
}

# Public Lambda permission
resource "aws_lambda_permission" "allow_all" {
  statement_id  = "AllowExecutionFromAnywhere"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_data.function_name
  principal     = "*"  # VIOLATION: Public access
}

# Weak password policy
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 6  # VIOLATION: Too short
  
  require_lowercase_characters = false  # VIOLATION: No lowercase required
  require_uppercase_characters = false  # VIOLATION: No uppercase required
  require_numbers             = false  # VIOLATION: No numbers required
  require_symbols             = false  # VIOLATION: No symbols required
  
  max_password_age = 365  # VIOLATION: Too long
}