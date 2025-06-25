# Policy Writing Guide

This guide explains how to write custom security policies for PolicyGuard using Open Policy Agent (OPA) and Rego.

## Table of Contents

- [Introduction](#introduction)
- [Policy Structure](#policy-structure)
- [Writing Your First Policy](#writing-your-first-policy)
- [Advanced Policy Patterns](#advanced-policy-patterns)
- [Testing Policies](#testing-policies)
- [Best Practices](#best-practices)
- [Common Patterns](#common-patterns)
- [Debugging Policies](#debugging-policies)

## Introduction

PolicyGuard uses Open Policy Agent (OPA) to evaluate infrastructure resources against security policies written in Rego. Rego is a declarative language designed for expressing policies over complex hierarchical data structures.

### Key Concepts

- **Package**: Namespace for policies
- **Rule**: A statement that defines when a violation occurs
- **Input**: The resource data being evaluated
- **Violation**: The output when a security issue is detected

## Policy Structure

All PolicyGuard policies follow this structure:

```rego
package policyguard

import future.keywords.contains
import future.keywords.if

# Rule description
deny[violation] {
    # Conditions that trigger the violation
    resource := input.resource
    resource.type == "resource_type"
    # ... additional conditions ...
    
    # Violation details
    violation := {
        "id": sprintf("unique-violation-id-%s", [resource.name]),
        "policy_id": "policy_name",
        "severity": "critical|high|medium|low",
        "message": "Human-readable description",
        "details": "Detailed explanation of the issue",
        "remediation": "How to fix the issue"
    }
}
```

### Required Fields

- **id**: Unique identifier for this specific violation
- **policy_id**: Identifier for the policy rule
- **severity**: Impact level (critical, high, medium, low)
- **message**: Brief description of the violation
- **details**: Detailed explanation
- **remediation**: Steps to fix the issue

## Writing Your First Policy

Let's write a simple policy that checks if S3 buckets have versioning enabled:

```rego
package policyguard

import future.keywords.contains
import future.keywords.if

# Ensure S3 buckets have versioning enabled
deny[violation] {
    # Check if resource is an S3 bucket
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Check if versioning is not enabled
    not resource.attributes.versioning.enabled
    
    # Create violation
    violation := {
        "id": sprintf("s3-no-versioning-%s", [resource.name]),
        "policy_id": "s3_bucket_versioning",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' does not have versioning enabled", [resource.name]),
        "details": "Versioning helps protect against accidental deletion and provides backup",
        "remediation": "Enable versioning by setting versioning.enabled = true"
    }
}
```

## Advanced Policy Patterns

### Checking Nested Attributes

```rego
# Check for encryption configuration
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Check if encryption configuration exists and is properly configured
    not resource.attributes.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
    
    violation := {
        "id": sprintf("s3-no-encryption-%s", [resource.name]),
        "policy_id": "s3_encryption",
        "severity": "high",
        "message": "S3 bucket missing encryption configuration",
        "details": "Buckets should have server-side encryption enabled",
        "remediation": "Add server_side_encryption_configuration block"
    }
}
```

### Checking Array Elements

```rego
# Check security group rules
deny[violation] {
    resource := input.resource
    resource.type == "aws_security_group"
    
    # Check each ingress rule
    some i
    rule := resource.attributes.ingress[i]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port == 22
    
    violation := {
        "id": sprintf("sg-ssh-open-%s", [resource.name]),
        "policy_id": "sg_ssh_restricted",
        "severity": "critical",
        "message": "Security group allows SSH from anywhere",
        "details": "SSH (port 22) should not be open to the internet",
        "remediation": "Restrict SSH access to specific IP ranges"
    }
}
```

### Using Helper Functions

```rego
# Helper function to check if a list contains a value
contains_value(list, value) {
    list[_] == value
}

# Use the helper function
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_policy"
    
    # Check if policy has dangerous actions
    statement := resource.attributes.policy.Statement[_]
    contains_value(statement.Action, "*")
    statement.Effect == "Allow"
    
    violation := {
        "id": sprintf("iam-wildcard-action-%s", [resource.name]),
        "policy_id": "iam_least_privilege",
        "severity": "high",
        "message": "IAM policy allows all actions",
        "details": "Policies should follow principle of least privilege",
        "remediation": "Specify exact actions instead of using wildcards"
    }
}
```

### Multiple Conditions with OR Logic

```rego
# Check for multiple weak encryption algorithms
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Get the encryption algorithm
    algorithm := resource.attributes.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
    
    # Check if it's a weak algorithm
    algorithm == "AES128"
    
    violation := {
        "id": sprintf("s3-weak-encryption-%s", [resource.name]),
        "policy_id": "s3_strong_encryption",
        "severity": "medium",
        "message": "S3 bucket uses weak encryption",
        "details": sprintf("Bucket uses %s which is considered weak", [algorithm]),
        "remediation": "Use AES256 or aws:kms for encryption"
    }
}

# Same check for another weak algorithm
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    algorithm := resource.attributes.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
    algorithm == "DES"
    
    violation := {
        "id": sprintf("s3-weak-encryption-%s", [resource.name]),
        "policy_id": "s3_strong_encryption",
        "severity": "high",
        "message": "S3 bucket uses very weak encryption",
        "details": sprintf("Bucket uses %s which is deprecated", [algorithm]),
        "remediation": "Use AES256 or aws:kms for encryption"
    }
}
```

## Testing Policies

### Unit Testing Policies

Create test files for your policies:

```rego
package policyguard_test

import data.policyguard

# Test that policy detects unencrypted S3 bucket
test_s3_encryption_violation {
    input := {
        "resource": {
            "type": "aws_s3_bucket",
            "name": "test-bucket",
            "attributes": {}
        }
    }
    
    violations := policyguard.deny[_]
    violations.policy_id == "s3_encryption"
}

# Test that policy passes for encrypted bucket
test_s3_encryption_pass {
    input := {
        "resource": {
            "type": "aws_s3_bucket",
            "name": "test-bucket",
            "attributes": {
                "server_side_encryption_configuration": {
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "AES256"
                        }
                    }
                }
            }
        }
    }
    
    violations := policyguard.deny[_]
    count(violations) == 0
}
```

### Running Tests

```bash
# Test a specific policy
opa test policies/aws/s3_encryption.rego policies/aws/s3_encryption_test.rego

# Test all policies
opa test policies/
```

## Best Practices

### 1. Use Descriptive Names

```rego
# Good: Clear what the policy checks
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    resource.attributes.acl == "public-read-write"
    # ...
}

# Bad: Unclear naming
deny[v] {
    r := input.resource
    r.type == "aws_s3_bucket"
    r.attributes.acl == "public-read-write"
    # ...
}
```

### 2. Provide Detailed Remediation

```rego
# Good: Specific remediation steps
violation := {
    # ...
    "remediation": "Set acl = 'private' and use bucket policies for fine-grained access control. See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
}

# Bad: Vague remediation
violation := {
    # ...
    "remediation": "Fix the bucket"
}
```

### 3. Use Appropriate Severity Levels

- **Critical**: Immediate security risk (e.g., public database, hardcoded credentials)
- **High**: Significant security issue (e.g., unencrypted data, weak authentication)
- **Medium**: Security concern (e.g., missing logging, outdated protocols)
- **Low**: Best practice violation (e.g., missing tags, naming conventions)

### 4. Handle Missing Attributes

```rego
# Good: Check if attribute exists
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Check if encryption config exists
    not resource.attributes.server_side_encryption_configuration
    
    violation := {
        # ...
        "message": "S3 bucket has no encryption configuration"
    }
}

# Also check for disabled encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Encryption exists but is disabled
    resource.attributes.server_side_encryption_configuration
    not resource.attributes.server_side_encryption_configuration.rule
    
    violation := {
        # ...
        "message": "S3 bucket has encryption disabled"
    }
}
```

### 5. Use Helper Functions for Complex Logic

```rego
# Helper to check CIDR ranges
is_public_cidr(cidr) {
    cidr == "0.0.0.0/0"
}

is_public_cidr(cidr) {
    cidr == "::/0"
}

# Use in policy
deny[violation] {
    resource := input.resource
    resource.type == "aws_security_group"
    
    rule := resource.attributes.ingress[_]
    cidr := rule.cidr_blocks[_]
    is_public_cidr(cidr)
    
    violation := {
        # ...
    }
}
```

## Common Patterns

### Resource Type Checking

```rego
# Single resource type
resource.type == "aws_s3_bucket"

# Multiple resource types
resource.type == "aws_s3_bucket"
resource.type == "aws_s3_bucket_object"

# Pattern matching
startswith(resource.type, "aws_s3_")
```

### Attribute Existence

```rego
# Check if attribute exists
resource.attributes.encryption

# Check if attribute doesn't exist
not resource.attributes.encryption

# Check if attribute is set to specific value
resource.attributes.encrypted == true

# Check if attribute is not set to specific value
resource.attributes.encrypted != true
```

### List Operations

```rego
# Check if list contains value
resource.attributes.cidr_blocks[_] == "0.0.0.0/0"

# Check if list is empty
count(resource.attributes.security_groups) == 0

# Check all items in list
all_encrypted := [encrypted | 
    volume := resource.attributes.volumes[_]
    encrypted := volume.encrypted
]
all(all_encrypted)
```

## Debugging Policies

### Using Print Statements

```rego
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    # Debug: Print resource attributes
    print("Resource attributes:", resource.attributes)
    
    not resource.attributes.versioning.enabled
    
    violation := {
        # ...
    }
}
```

### Testing with OPA REPL

```bash
# Start OPA REPL
opa run

# Load your policy
> import data.policyguard

# Test with sample input
> input := {"resource": {"type": "aws_s3_bucket", "name": "test", "attributes": {}}}
> data.policyguard.deny[x]
```

### Common Issues

1. **Undefined references**: Make sure all variables are defined
2. **Type mismatches**: Check data types (string vs boolean vs number)
3. **Missing imports**: Add necessary imports at the top of the file
4. **Syntax errors**: Use `opa fmt` to format and check syntax

## Examples

### Complete S3 Security Policy

```rego
package policyguard

import future.keywords.contains
import future.keywords.if

# Check for public access
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    acl := resource.attributes.acl
    acl == "public-read"
    
    violation := {
        "id": sprintf("s3-public-read-%s", [resource.name]),
        "policy_id": "s3_no_public_access",
        "severity": "high",
        "message": sprintf("S3 bucket '%s' allows public read access", [resource.name]),
        "details": "S3 buckets should not allow public read access unless explicitly required",
        "remediation": "Set acl = 'private' and use bucket policies for controlled access"
    }
}

deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    acl := resource.attributes.acl
    acl == "public-read-write"
    
    violation := {
        "id": sprintf("s3-public-write-%s", [resource.name]),
        "policy_id": "s3_no_public_access",
        "severity": "critical",
        "message": sprintf("S3 bucket '%s' allows public write access", [resource.name]),
        "details": "S3 buckets must never allow public write access",
        "remediation": "Immediately set acl = 'private' and review bucket contents"
    }
}

# Check for encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    not resource.attributes.server_side_encryption_configuration
    
    violation := {
        "id": sprintf("s3-no-encryption-%s", [resource.name]),
        "policy_id": "s3_encryption_required",
        "severity": "high",
        "message": sprintf("S3 bucket '%s' does not have encryption enabled", [resource.name]),
        "details": "All S3 buckets must have server-side encryption enabled",
        "remediation": "Add server_side_encryption_configuration with AES256 or KMS"
    }
}

# Check for versioning
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    not resource.attributes.versioning.enabled
    
    violation := {
        "id": sprintf("s3-no-versioning-%s", [resource.name]),
        "policy_id": "s3_versioning_required",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' does not have versioning enabled", [resource.name]),
        "details": "Versioning protects against accidental deletion and provides data recovery",
        "remediation": "Enable versioning by setting versioning.enabled = true"
    }
}

# Check for logging
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    not resource.attributes.logging
    
    violation := {
        "id": sprintf("s3-no-logging-%s", [resource.name]),
        "policy_id": "s3_logging_required",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' does not have access logging enabled", [resource.name]),
        "details": "Access logging helps with security auditing and compliance",
        "remediation": "Enable logging by adding a logging configuration block"
    }
}
```

### RDS Security Policy

```rego
package policyguard

import future.keywords.contains
import future.keywords.if

# Check for encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    not resource.attributes.storage_encrypted
    
    violation := {
        "id": sprintf("rds-no-encryption-%s", [resource.name]),
        "policy_id": "rds_encryption_required",
        "severity": "high",
        "message": sprintf("RDS instance '%s' does not have encryption enabled", [resource.name]),
        "details": "RDS instances must have encryption at rest enabled",
        "remediation": "Set storage_encrypted = true"
    }
}

# Check for backup retention
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    backup_retention := resource.attributes.backup_retention_period
    backup_retention < 7
    
    violation := {
        "id": sprintf("rds-short-backup-%s", [resource.name]),
        "policy_id": "rds_backup_retention",
        "severity": "medium",
        "message": sprintf("RDS instance '%s' has backup retention of only %d days", [resource.name, backup_retention]),
        "details": "RDS instances should have at least 7 days of backup retention",
        "remediation": "Set backup_retention_period to at least 7"
    }
}

# Check for public accessibility
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    resource.attributes.publicly_accessible == true
    
    violation := {
        "id": sprintf("rds-public-access-%s", [resource.name]),
        "policy_id": "rds_no_public_access",
        "severity": "critical",
        "message": sprintf("RDS instance '%s' is publicly accessible", [resource.name]),
        "details": "RDS instances should not be directly accessible from the internet",
        "remediation": "Set publicly_accessible = false and use VPN or bastion hosts"
    }
}
```

## Next Steps

1. Review existing policies in the `policies/` directory
2. Start with simple policies and gradually add complexity
3. Test your policies thoroughly
4. Contribute your policies back to the community

For more information on Rego and OPA:
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Playground](https://play.openpolicyagent.org/)
- [Rego Style Guide](https://github.com/StyraInc/rego-style-guide)