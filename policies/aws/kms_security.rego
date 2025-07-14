package policyguard

import future.keywords.contains
import future.keywords.if

# Deny KMS keys without rotation enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check if key rotation is disabled
    resource.attributes.enable_key_rotation == false
    
    violation := {
        "id": sprintf("kms-key-no-rotation-%s", [resource.name]),
        "policy_id": "kms_key_rotation",
        "severity": "high",
        "message": sprintf("KMS key '%s' does not have automatic rotation enabled", [resource.name]),
        "details": "KMS keys should have automatic rotation enabled to enhance security by regularly changing the key material",
        "remediation": "Set enable_key_rotation to true"
    }
}

# Deny KMS keys without proper deletion window
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check for short deletion window (less than 7 days)
    resource.attributes.deletion_window_in_days < 7
    
    violation := {
        "id": sprintf("kms-key-short-deletion-window-%s", [resource.name]),
        "policy_id": "kms_deletion_protection",
        "severity": "medium",
        "message": sprintf("KMS key '%s' has a short deletion window", [resource.name]),
        "details": "KMS keys should have a deletion window of at least 7 days to prevent accidental deletion",
        "remediation": "Set deletion_window_in_days to at least 7 (recommended: 30 days)"
    }
}

# Deny KMS keys without description
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check if description is missing or empty
    not resource.attributes.description
    
    violation := {
        "id": sprintf("kms-key-no-description-%s", [resource.name]),
        "policy_id": "kms_key_documentation",
        "severity": "low",
        "message": sprintf("KMS key '%s' lacks a description", [resource.name]),
        "details": "KMS keys should have clear descriptions indicating their purpose and usage",
        "remediation": "Add a descriptive 'description' attribute explaining the key's purpose"
    }
}

# Check KMS key policies for overly permissive access
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check if policy allows all actions for all principals (*)
    contains(resource.attributes.policy, "\"Principal\": \"*\"")
    contains(resource.attributes.policy, "\"Action\": \"*\"")
    
    violation := {
        "id": sprintf("kms-key-overly-permissive-%s", [resource.name]),
        "policy_id": "kms_key_policy_security",
        "severity": "critical",
        "message": sprintf("KMS key '%s' has overly permissive policy", [resource.name]),
        "details": "KMS key policies should follow least privilege principle and not allow all actions for all principals",
        "remediation": "Review and restrict the key policy to specific principals and actions"
    }
}

# Check for KMS keys allowing decrypt to all principals
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check if policy allows decrypt to all principals
    contains(resource.attributes.policy, "\"Principal\": \"*\"")
    contains(resource.attributes.policy, "kms:Decrypt")
    
    violation := {
        "id": sprintf("kms-key-public-decrypt-%s", [resource.name]),
        "policy_id": "kms_decrypt_permissions",
        "severity": "critical",
        "message": sprintf("KMS key '%s' allows decrypt access to all principals", [resource.name]),
        "details": "KMS keys should not allow decrypt permissions to all principals (*) as this compromises data security",
        "remediation": "Restrict decrypt permissions to specific AWS accounts, IAM roles, or users"
    }
}

# Warn about KMS keys without proper tagging
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check for missing common tags
    not resource.attributes.tags.Environment
    
    violation := {
        "id": sprintf("kms-key-no-environment-tag-%s", [resource.name]),
        "policy_id": "kms_key_tagging",
        "severity": "low",
        "message": sprintf("KMS key '%s' lacks Environment tag", [resource.name]),
        "details": "KMS keys should be properly tagged for resource management and cost allocation",
        "remediation": "Add tags including Environment, Purpose, and Owner for better resource management"
    }
}

# Check KMS aliases for proper naming conventions
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_alias"
    
    # Check if alias doesn't follow naming convention (should start with alias/)
    not startswith(resource.attributes.name, "alias/")
    
    violation := {
        "id": sprintf("kms-alias-invalid-name-%s", [resource.name]),
        "policy_id": "kms_alias_naming",
        "severity": "medium",
        "message": sprintf("KMS alias '%s' does not follow naming convention", [resource.name]),
        "details": "KMS alias names must start with 'alias/' prefix",
        "remediation": "Update alias name to start with 'alias/' (e.g., 'alias/my-key')"
    }
}

# Check for KMS keys used across multiple services without proper organization
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_key"
    
    # Check if key description suggests multi-service usage but lacks clear purpose
    desc := lower(resource.attributes.description)
    contains(desc, "general")
    contains(desc, "multiple")
    
    violation := {
        "id": sprintf("kms-key-multi-service-%s", [resource.name]),
        "policy_id": "kms_key_organization",
        "severity": "low",
        "message": sprintf("KMS key '%s' appears to be used for multiple services", [resource.name]),
        "details": "Consider using separate KMS keys for different services or data types for better security isolation",
        "remediation": "Create service-specific KMS keys or clearly document the multi-service usage rationale"
    }
}

# Check for KMS grants that might be overly permissive
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_grant"
    
    # Check if grant allows all operations
    operations := resource.attributes.operations
    count(operations) > 10  # Arbitrary threshold for "too many operations"
    
    violation := {
        "id": sprintf("kms-grant-too-permissive-%s", [resource.name]),
        "policy_id": "kms_grant_permissions",
        "severity": "medium",
        "message": sprintf("KMS grant '%s' allows too many operations", [resource.name]),
        "details": "KMS grants should follow least privilege principle and only grant necessary operations",
        "remediation": "Review and reduce the operations list to only those required"
    }
}

# Check for KMS external key usage without proper validation
deny[violation] {
    resource := input.resource
    resource.type == "aws_kms_external_key"
    
    # External keys require careful management
    not resource.attributes.valid_to
    
    violation := {
        "id": sprintf("kms-external-key-no-expiry-%s", [resource.name]),
        "policy_id": "kms_external_key_management",
        "severity": "medium",
        "message": sprintf("KMS external key '%s' has no expiration date", [resource.name]),
        "details": "External KMS keys should have expiration dates for better key lifecycle management",
        "remediation": "Set valid_to attribute to define key expiration date"
    }
}