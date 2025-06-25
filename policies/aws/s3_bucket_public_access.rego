package policyguard

import future.keywords.contains
import future.keywords.if

# Deny S3 buckets with public-read or public-read-write ACL
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    acl := resource.attributes.acl
    {"public-read", "public-read-write"}[acl]
    
    violation := {
        "id": sprintf("s3-public-acl-%s", [resource.name]),
        "policy_id": "s3_bucket_public_access",
        "severity": "critical",
        "message": sprintf("S3 bucket '%s' has public ACL '%s'", [resource.name, acl]),
        "details": "S3 buckets should not allow public access through ACLs",
        "remediation": "Set acl to 'private' and use bucket policies for controlled access"
    }
}

# Deny S3 bucket public access block with public access allowed
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket_public_access_block"
    
    # Check if any public access is allowed
    public_access_allowed := [
        resource.attributes.block_public_acls == false,
        resource.attributes.block_public_policy == false,
        resource.attributes.ignore_public_acls == false,
        resource.attributes.restrict_public_buckets == false
    ]
    
    public_access_allowed[_] == true
    
    violation := {
        "id": sprintf("s3-public-access-block-%s", [resource.name]),
        "policy_id": "s3_bucket_public_access",
        "severity": "high",
        "message": sprintf("S3 bucket public access block '%s' allows public access", [resource.name]),
        "details": "All public access block settings should be set to true",
        "remediation": "Set all public access block attributes to true"
    }
}

# Deny S3 buckets without logging enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Check if logging is not configured
    not resource.attributes.logging
    
    violation := {
        "id": sprintf("s3-no-logging-%s", [resource.name]),
        "policy_id": "s3_bucket_logging",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' does not have access logging enabled", [resource.name]),
        "details": "S3 bucket access logging helps with security auditing and compliance",
        "remediation": "Add a logging configuration block with target_bucket and target_prefix"
    }
}