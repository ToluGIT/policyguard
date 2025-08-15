package policyguard

import future.keywords.contains
import future.keywords.if

# Helper function to check if protocol is HTTP or HTTPS
is_http_protocol(protocol) {
    protocol == "http"
}

is_http_protocol(protocol) {
    protocol == "https"
}

# Deny SNS topics without server-side encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic"
    
    # Check if server-side encryption is missing
    not resource.attributes.kms_master_key_id
    
    violation := {
        "id": sprintf("sns-no-encryption-%s", [resource.name]),
        "policy_id": "sns_topic_encryption",
        "severity": "high",
        "message": sprintf("SNS topic '%s' does not have server-side encryption enabled", [resource.name]),
        "details": "SNS topics should have server-side encryption enabled to protect sensitive message data",
        "remediation": "Add kms_master_key_id attribute referencing a KMS key"
    }
}

# Deny SNS topics with public access
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic_policy"
    
    # Check if policy allows public access
    policy := json.unmarshal(resource.attributes.policy)
    statement := policy.Statement[_]
    
    # Check for public principal ("*")
    statement.Principal == "*" 
    
    # Check for public principal in AWS format ({"AWS": "*"})
    is_public_principal(statement)
    
    violation := {
        "id": sprintf("sns-public-access-%s", [resource.name]),
        "policy_id": "sns_public_access",
        "severity": "critical",
        "message": sprintf("SNS topic policy '%s' allows public access", [resource.name]),
        "details": "SNS topic policies should not allow public access as it creates security vulnerabilities",
        "remediation": "Restrict the Principal in the policy to specific AWS accounts or IAM entities"
    }
}

# Helper function to check for public principal in AWS format
is_public_principal(statement) {
    statement.Principal.AWS == "*"
}

# Deny SNS topics with no tags for resource management
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic"
    
    # Check if required tags are missing
    not resource.attributes.tags
    
    violation := {
        "id": sprintf("sns-no-tags-%s", [resource.name]),
        "policy_id": "sns_topic_tagging",
        "severity": "low",
        "message": sprintf("SNS topic '%s' has no resource tags", [resource.name]),
        "details": "SNS topics should have proper resource tags for better organization and cost allocation",
        "remediation": "Add tags including Environment, Owner, and Purpose"
    }
}

# Check for SNS FIFO topics without content-based deduplication when required
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic"
    
    # Check if it's a FIFO topic (ends with .fifo)
    endswith(resource.attributes.name, ".fifo")
    
    # Check if content-based deduplication is disabled
    resource.attributes.content_based_deduplication == false
    
    violation := {
        "id": sprintf("sns-fifo-no-dedup-%s", [resource.name]),
        "policy_id": "sns_fifo_deduplication",
        "severity": "medium",
        "message": sprintf("FIFO SNS topic '%s' doesn't have content-based deduplication enabled", [resource.name]),
        "details": "FIFO topics should generally have content-based deduplication enabled to prevent duplicate messages",
        "remediation": "Set content_based_deduplication = true for the FIFO topic"
    }
}

# Check for SNS topics with large message sizes without raw message delivery
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic_subscription"
    
    # Check for SQS protocol without raw message delivery
    resource.attributes.protocol == "sqs"
    resource.attributes.raw_message_delivery == false
    
    violation := {
        "id": sprintf("sns-no-raw-delivery-%s", [resource.name]),
        "policy_id": "sns_message_delivery",
        "severity": "low",
        "message": sprintf("SNS topic subscription '%s' to SQS doesn't use raw message delivery", [resource.name]),
        "details": "SNS to SQS subscriptions should use raw message delivery for better performance and to avoid double encoding",
        "remediation": "Set raw_message_delivery = true for SQS protocol subscriptions"
    }
}

# Check for HTTP/HTTPS subscriptions without proper authentication
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic_subscription"
    
    # Check for HTTP/HTTPS protocols
    protocol := resource.attributes.protocol
    is_http_protocol(protocol)
    
    # Check if authentication is missing
    not resource.attributes.endpoint_auto_confirms
    not resource.attributes.confirmation_timeout_in_minutes
    
    violation := {
        "id": sprintf("sns-http-no-auth-%s", [resource.name]),
        "policy_id": "sns_http_authentication",
        "severity": "medium",
        "message": sprintf("SNS topic subscription '%s' using %s protocol lacks endpoint confirmation settings", [resource.name, protocol]),
        "details": "HTTP/HTTPS subscriptions should have proper authentication and confirmation settings",
        "remediation": "Set appropriate endpoint_auto_confirms and confirmation_timeout_in_minutes values"
    }
}

# Warn about email protocol subscriptions (plain email doesn't support encryption)
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic_subscription"
    
    # Check for email protocol
    resource.attributes.protocol == "email"
    
    violation := {
        "id": sprintf("sns-email-subscription-%s", [resource.name]),
        "policy_id": "sns_secure_delivery",
        "severity": "medium",
        "message": sprintf("SNS topic subscription '%s' uses plain email protocol", [resource.name]),
        "details": "Email protocol subscriptions don't support message encryption and should be avoided for sensitive data",
        "remediation": "Consider using email-json, https, or other protocols that support encryption"
    }
}

# Check for cross-account subscriptions without proper authorization
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic_subscription"
    
    # Check if subscription is from another account
    contains(resource.attributes.topic_arn, ":")
    account_parts := split(resource.attributes.topic_arn, ":")
    account_id := account_parts[4]
    
    # Assume current account ID is different (simplified check)
    contains(resource.attributes.subscription_role_arn, ":")
    role_parts := split(resource.attributes.subscription_role_arn, ":")
    role_account_id := role_parts[4]
    
    account_id != role_account_id
    
    # No subscription_role_arn specified
    not resource.attributes.subscription_role_arn
    
    violation := {
        "id": sprintf("sns-cross-account-no-auth-%s", [resource.name]),
        "policy_id": "sns_cross_account_security",
        "severity": "high",
        "message": sprintf("SNS topic subscription '%s' is cross-account without proper authorization", [resource.name]),
        "details": "Cross-account SNS subscriptions should have a subscription_role_arn defined for proper authorization",
        "remediation": "Add a subscription_role_arn with appropriate permissions"
    }
}

# Check for missing encryption in transit for HTTPS subscriptions
deny[violation] {
    resource := input.resource
    resource.type == "aws_sns_topic_subscription"
    
    # Check if using HTTP instead of HTTPS
    resource.attributes.protocol == "http"
    
    violation := {
        "id": sprintf("sns-http-no-encryption-%s", [resource.name]),
        "policy_id": "sns_encryption_in_transit",
        "severity": "high",
        "message": sprintf("SNS topic subscription '%s' uses HTTP protocol without encryption", [resource.name]),
        "details": "SNS topic subscriptions should use HTTPS instead of HTTP to ensure encryption in transit",
        "remediation": "Change the protocol from 'http' to 'https' and update the endpoint accordingly"
    }
}