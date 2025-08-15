# Example file demonstrating Terraform module usage

# Using a local module
module "secure_bucket" {
  source = "./modules"
  
  bucket_name       = "my-secure-bucket"
  enable_versioning = true
  
  tags = {
    Environment = "Production"
    Owner       = "Security Team"
    Purpose     = "Secure Data Storage"
  }
}

# Using a remote module with a specific version
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = false

  tags = {
    Environment = "Production"
    Name        = "Main VPC"
    ManagedBy   = "Terraform"
  }
}

# Using a module with a non-standard structure and path
module "custom_security_group" {
  source = "./modules/security"
  
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = module.vpc.vpc_id
  
  # Define ingress rules
  ingress_rules = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTPS"
    }
  ]
  
  # Define egress rules
  egress_rules = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow all outbound traffic"
    }
  ]
  
  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Create a resource using outputs from a module
resource "aws_s3_bucket_policy" "example" {
  bucket = module.secure_bucket.bucket_id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/ReadOnlyRole"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          module.secure_bucket.bucket_arn,
          "${module.secure_bucket.bucket_arn}/*"
        ]
      }
    ]
  })
}