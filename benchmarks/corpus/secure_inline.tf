# Benchmark fixture: resources secured using the INLINE attribute style that
# PolicyGuard's single-resource policies understand. A correct policy set
# should produce ZERO core-set findings here (these are the true negatives).

resource "aws_s3_bucket" "secure" {
  bucket = "bench-secure-inline"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  logging {
    target_bucket = "bench-log-bucket"
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_instance" "hardened" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }
}

resource "aws_security_group" "restricted" {
  name = "bench-restricted"

  ingress {
    description = "SSH from internal CIDR only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "hardened" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 14
}
