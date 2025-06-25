package policyguard

import future.keywords.contains
import future.keywords.if

# Test policy for integration testing
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    resource.attributes.acl == "public-read-write"
    
    violation := {
        "id": sprintf("test-s3-public-%s", [resource.name]),
        "policy_id": "test_s3_public",
        "severity": "critical",
        "message": sprintf("Test: S3 bucket '%s' is public", [resource.name]),
        "details": "This is a test policy",
        "remediation": "Set acl to private"
    }
}