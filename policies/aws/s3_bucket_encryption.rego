package policyguard

import future.keywords.contains
import future.keywords.if

# Deny S3 buckets without server-side encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Check if server_side_encryption_configuration is missing
    not resource.attributes.server_side_encryption_configuration
    
    violation := {
        "id": sprintf("s3-no-encryption-%s", [resource.name]),
        "policy_id": "s3_bucket_encryption",
        "severity": "high",
        "message": sprintf("S3 bucket '%s' does not have server-side encryption enabled", [resource.name]),
        "details": "S3 buckets should have server-side encryption enabled to protect data at rest",
        "remediation": "Add a server_side_encryption_configuration block with AES256 or aws:kms encryption"
    }
}

# Deny S3 buckets with encryption but using deprecated settings
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Check for deprecated encryption settings
    resource.attributes.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm == "AES128"
    
    violation := {
        "id": sprintf("s3-weak-encryption-%s", [resource.name]),
        "policy_id": "s3_bucket_encryption",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' uses weak encryption algorithm", [resource.name]),
        "details": "AES128 is deprecated, use AES256 or aws:kms instead",
        "remediation": "Update sse_algorithm to 'AES256' or 'aws:kms'"
    }
}