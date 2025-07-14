# Example of SECURE infrastructure configuration
# This file demonstrates security best practices and should achieve a high pass rate

# Secure S3 bucket with all security features enabled
resource "aws_s3_bucket" "secure_app_data" {
  bucket = "myapp-secure-data-bucket"
  
  tags = {
    Name        = "Secure App Data"
    Environment = "production"
    Security    = "compliant"
  }
}

# Private ACL for the bucket
resource "aws_s3_bucket_acl" "secure_app_data" {
  bucket = aws_s3_bucket.secure_app_data.id
  acl    = "private"
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_app_data" {
  bucket = aws_s3_bucket.secure_app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "secure_app_data" {
  bucket = aws_s3_bucket.secure_app_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "secure_app_data" {
  bucket = aws_s3_bucket.secure_app_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable access logging (requires a separate log bucket)
resource "aws_s3_bucket" "access_logs" {
  bucket = "myapp-access-logs-bucket"
  
  tags = {
    Name = "Access Log Bucket"
  }
}

resource "aws_s3_bucket_acl" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  acl    = "private"
}

resource "aws_s3_bucket_logging" "secure_app_data" {
  bucket = aws_s3_bucket.secure_app_data.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/"
}

# Secure EC2 instance with all security features
resource "aws_instance" "secure_web_server" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  
  # No public IP - private instance
  associate_public_ip_address = false
  
  # Use a secure security group
  vpc_security_group_ids = [aws_security_group.secure_web.id]
  
  # Encrypted root volume
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 20
  }
  
  # Enforce IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  
  tags = {
    Name = "Secure Web Server"
    Environment = "production"
  }
}

# Secure security group with restricted access
resource "aws_security_group" "secure_web" {
  name_prefix = "secure-web-"
  description = "Secure security group for web servers"
  
  # Only allow HTTPS from specific CIDR blocks
  ingress {
    description = "HTTPS from corporate network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Private network only
  }
  
  # Restricted outbound access
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    description = "HTTP outbound for package updates"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "Secure Web Security Group"
  }
}

# Secure EBS volume
resource "aws_ebs_volume" "secure_data" {
  availability_zone = "us-west-2a"
  size              = 100
  
  # Encrypted volume
  encrypted = true
  type      = "gp3"
  
  tags = {
    Name = "Secure Data Volume"
  }
}

# Secure RDS instance (if policies exist for RDS)
resource "aws_db_instance" "secure_database" {
  identifier = "secure-app-db"
  
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  
  # Encryption enabled
  storage_encrypted = true
  
  # Private access only
  publicly_accessible = false
  
  # Database credentials (in production, use secrets manager)
  db_name  = "appdb"
  username = "dbadmin"
  password = "SuperSecurePassword123!"  # Use AWS Secrets Manager in production
  
  # Backup configuration
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  # Security
  deletion_protection = true
  skip_final_snapshot = false
  
  tags = {
    Name = "Secure Application Database"
  }
}

# KMS key for additional encryption (good practice)
resource "aws_kms_key" "app_encryption" {
  description = "KMS key for application encryption"
  
  tags = {
    Name = "App Encryption Key"
  }
}

resource "aws_kms_alias" "app_encryption" {
  name          = "alias/app-encryption"
  target_key_id = aws_kms_key.app_encryption.key_id
}