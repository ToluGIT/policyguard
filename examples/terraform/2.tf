# iam-violations.tf
# This configuration will trigger multiple IAM policy violations

# IAM policy with wildcard actions (violation: iam-wildcard-action)
resource "aws_iam_policy" "wildcard_actions" {
  name = "overly-permissive-policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]  # VIOLATION: Wildcard action
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}

# IAM policy with wildcard resources (violation: iam-wildcard-resource)
resource "aws_iam_policy" "wildcard_resources" {
  name = "all-resources-policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "*"  # VIOLATION: Wildcard resource
      }
    ]
  })
}

# IAM role without MFA (violation: iam-role-no-mfa)
resource "aws_iam_role" "no_mfa_role" {
  name = "admin-role-no-mfa"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"  # User principal without MFA
        }
        Action = "sts:AssumeRole"
        # VIOLATION: No MFA condition
      }
    ]
  })
}

# IAM user with inline policy (violation: iam-inline-policy)
resource "aws_iam_user_policy" "inline_policy" {
  name = "user-inline-policy"
  user = "test-user"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = "arn:aws:s3:::example-bucket"
      }
    ]
  })
}

# IAM user without MFA (violation: iam-user-no-mfa)
resource "aws_iam_user" "no_mfa_user" {
  name = "console-user-no-mfa"
  # VIOLATION: No MFA enforcement (detected by absence of MFA policy)
}

# Overly permissive trust policy (violation: iam-role-trust-everyone)
resource "aws_iam_role" "trust_everyone" {
  name = "public-assumable-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # VIOLATION: Anyone can assume this role
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Weak password policy (multiple violations)
resource "aws_iam_account_password_policy" "weak_policy" {
  minimum_password_length        = 8   # VIOLATION: Less than 14
  require_uppercase_characters   = false  # VIOLATION: No uppercase required
  require_lowercase_characters   = false  # VIOLATION: No lowercase required
  require_numbers               = false  # VIOLATION: No numbers required
  require_symbols               = false  # VIOLATION: No symbols required
  max_password_age              = 365  # VIOLATION: More than 90 days
  password_reuse_prevention     = 1
}

# IAM access key (violation: iam-access-key-rotation)
resource "aws_iam_access_key" "user_key" {
  name = "user-access-key"
  user = "service-account"
  # VIOLATION: Will be flagged for rotation policy
}