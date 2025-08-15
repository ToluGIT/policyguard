package policyguard

import future.keywords.contains
import future.keywords.if

# Deny SQS queues without server-side encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Check if server-side encryption is missing
    not resource.attributes.kms_master_key_id
    resource.attributes.sqs_managed_sse_enabled == false
    
    violation := {
        "id": sprintf("sqs-no-encryption-%s", [resource.name]),
        "policy_id": "sqs_queue_encryption",
        "severity": "high",
        "message": sprintf("SQS queue '%s' does not have encryption enabled", [resource.name]),
        "details": "SQS queues should have either KMS encryption or SQS managed encryption enabled to protect sensitive message data",
        "remediation": "Add kms_master_key_id attribute or set sqs_managed_sse_enabled = true"
    }
}

# Deny SQS queues with public access policy
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue_policy"
    
    # Check if policy allows public access
    policy := json.unmarshal(resource.attributes.policy)
    statement := policy.Statement[_]
    
    # Check for public principal ("*")
    statement.Principal == "*" 
    
    # Check for public principal in AWS format ({"AWS": "*"})
    is_public_principal(statement)
    
    violation := {
        "id": sprintf("sqs-public-access-%s", [resource.name]),
        "policy_id": "sqs_public_access",
        "severity": "critical",
        "message": sprintf("SQS queue policy '%s' allows public access", [resource.name]),
        "details": "SQS queue policies should not allow public access as it creates security vulnerabilities",
        "remediation": "Restrict the Principal in the policy to specific AWS accounts or IAM entities"
    }
}

# Helper function to check for public principal in AWS format
is_public_principal(statement) {
    statement.Principal.AWS == "*"
}

# Check for DLQ (Dead Letter Queue) configuration for standard queues
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Skip check for FIFO queues
    not endswith(resource.attributes.name, ".fifo")
    
    # Check if DLQ is missing
    not resource.attributes.redrive_policy
    
    violation := {
        "id": sprintf("sqs-no-dlq-%s", [resource.name]),
        "policy_id": "sqs_dead_letter_queue",
        "severity": "medium",
        "message": sprintf("SQS queue '%s' does not have a dead letter queue configured", [resource.name]),
        "details": "SQS queues should have a dead letter queue configured to capture failed messages",
        "remediation": "Add a redrive_policy with a dead letter queue ARN and maxReceiveCount"
    }
}

# Warn about SQS queues with no tags for resource management
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Check if required tags are missing
    not resource.attributes.tags
    
    violation := {
        "id": sprintf("sqs-no-tags-%s", [resource.name]),
        "policy_id": "sqs_queue_tagging",
        "severity": "low",
        "message": sprintf("SQS queue '%s' has no resource tags", [resource.name]),
        "details": "SQS queues should have proper resource tags for better organization and cost allocation",
        "remediation": "Add tags including Environment, Owner, and Purpose"
    }
}

# Check for weak FIFO queue configuration
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Check if it's a FIFO queue
    endswith(resource.attributes.name, ".fifo")
    
    # Check if content-based deduplication is disabled and deduplication_scope is not provided
    resource.attributes.content_based_deduplication == false
    not resource.attributes.deduplication_scope
    
    violation := {
        "id": sprintf("sqs-fifo-weak-config-%s", [resource.name]),
        "policy_id": "sqs_fifo_configuration",
        "severity": "medium",
        "message": sprintf("FIFO SQS queue '%s' has suboptimal deduplication configuration", [resource.name]),
        "details": "FIFO queues should have content-based deduplication enabled or a specified deduplication scope",
        "remediation": "Set content_based_deduplication = true or specify deduplication_scope"
    }
}

# Check for overly permissive visibility timeout
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Check if visibility timeout is too high (over 12 hours)
    resource.attributes.visibility_timeout_seconds > 43200
    
    violation := {
        "id": sprintf("sqs-high-visibility-%s", [resource.name]),
        "policy_id": "sqs_visibility_timeout",
        "severity": "medium",
        "message": sprintf("SQS queue '%s' has an excessive visibility timeout", [resource.name]),
        "details": "SQS queue visibility timeout exceeds 12 hours which may cause processing delays or issues",
        "remediation": "Reduce visibility_timeout_seconds to an appropriate value (30-3600 seconds is common)"
    }
}

# Check for too short message retention period
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Check if message retention period is too short (less than 1 day)
    resource.attributes.message_retention_seconds < 86400
    
    violation := {
        "id": sprintf("sqs-short-retention-%s", [resource.name]),
        "policy_id": "sqs_message_retention",
        "severity": "medium",
        "message": sprintf("SQS queue '%s' has a very short message retention period", [resource.name]),
        "details": "SQS queue message retention period is less than 1 day, which might lead to premature message loss",
        "remediation": "Increase message_retention_seconds to at least 86400 (1 day) or higher if needed"
    }
}

# Check for missing queue encryption in high-security queues
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue"
    
    # Check queue name for security indicators
    name := lower(resource.attributes.name)
    contains_security_term(name)
    
    # Check if server-side encryption is missing
    not resource.attributes.kms_master_key_id
    not resource.attributes.sqs_managed_sse_enabled
    
    violation := {
        "id": sprintf("sqs-sensitive-no-encryption-%s", [resource.name]),
        "policy_id": "sqs_sensitive_data_protection",
        "severity": "high",
        "message": sprintf("SQS queue '%s' appears to handle sensitive data but lacks encryption", [resource.name]),
        "details": "SQS queues with names suggesting they contain sensitive information must have encryption enabled",
        "remediation": "Add kms_master_key_id attribute or set sqs_managed_sse_enabled = true"
    }
}

# Helper function to check for security-related terms in queue name
contains_security_term(name) {
    security_terms := ["secure", "sensitive", "confidential", "pii", "payment", "financial", "password", "secret"]
    term := security_terms[_]
    contains(name, term)
}

# Check for overly permissive SQS access policy
deny[violation] {
    resource := input.resource
    resource.type == "aws_sqs_queue_policy"
    
    # Check for broad actions in policy
    policy := json.unmarshal(resource.attributes.policy)
    statement := policy.Statement[_]
    
    # Check for wildcard actions
    statement.Action == "*" 
    statement.Action == "sqs:*"
    
    violation := {
        "id": sprintf("sqs-overly-permissive-%s", [resource.name]),
        "policy_id": "sqs_policy_principle",
        "severity": "high",
        "message": sprintf("SQS queue policy '%s' grants overly permissive actions", [resource.name]),
        "details": "SQS queue policies should follow the principle of least privilege and grant only necessary actions",
        "remediation": "Specify only the required SQS actions instead of using wildcards like '*' or 'sqs:*'"
    }
}