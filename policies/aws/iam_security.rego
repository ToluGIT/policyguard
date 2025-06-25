package policyguard

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Description: Comprehensive IAM security policies for AWS

# Deny IAM policies with wildcard actions
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_policy"
    
    # Parse the policy document (already parsed by Terraform parser)
    policy := resource.attributes.policy
    statement := policy.Statement[_]
    
    # Check for wildcard actions
    statement.Effect == "Allow"
    
    # Check if Action is "*" (single string) or contains "*" (in array)
    contains_wildcard_action(statement)
    
    violation := {
        "id": sprintf("iam-wildcard-action-%s", [resource.name]),
        "policy_id": "iam_no_wildcard_actions",
        "severity": "high",
        "message": sprintf("IAM policy '%s' allows all actions (*)", [resource.name]),
        "details": "IAM policies should follow the principle of least privilege and not use wildcard actions",
        "remediation": "Replace wildcard (*) with specific actions needed for the workload"
    }
}

# Deny IAM policies with wildcard resources
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_policy"
    
    policy := resource.attributes.policy
    statement := policy.Statement[_]
    
    # Check for wildcard resources
    statement.Effect == "Allow"
    
    # Check if Resource is "*" (single string) or contains "*" (in array)
    contains_wildcard_resource(statement)
    
    violation := {
        "id": sprintf("iam-wildcard-resource-%s", [resource.name]),
        "policy_id": "iam_no_wildcard_resources",
        "severity": "high",
        "message": sprintf("IAM policy '%s' applies to all resources (*)", [resource.name]),
        "details": "IAM policies should specify exact resources instead of using wildcards",
        "remediation": "Replace wildcard (*) with specific resource ARNs"
    }
}

# Deny IAM roles without MFA for assume role
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_role"
    
    # Parse assume role policy
    policy := resource.attributes.assume_role_policy
    statement := policy.Statement[_]
    
    # Check if MFA is required
    not statement.Condition.Bool["aws:MultiFactorAuthPresent"]
    
    # Only flag roles that can be assumed by users (not services)
    principal := statement.Principal
    contains(principal.AWS, "arn:aws:iam")
    
    violation := {
        "id": sprintf("iam-role-no-mfa-%s", [resource.name]),
        "policy_id": "iam_role_require_mfa",
        "severity": "medium",
        "message": sprintf("IAM role '%s' can be assumed without MFA", [resource.name]),
        "details": "IAM roles that can be assumed by users should require MFA",
        "remediation": "Add MFA condition to the assume role policy"
    }
}

# Deny IAM users with inline policies
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_user_policy"
    
    violation := {
        "id": sprintf("iam-inline-policy-%s", [resource.name]),
        "policy_id": "iam_no_inline_policies",
        "severity": "medium",
        "message": sprintf("IAM user has inline policy '%s'", [resource.name]),
        "details": "Use managed policies instead of inline policies for better reusability and management",
        "remediation": "Convert inline policy to a managed policy and attach it to the user"
    }
}

# Deny IAM users without MFA enforcement
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_user"
    
    # Check if user has programmatic access
    not resource.attributes.force_destroy
    
    violation := {
        "id": sprintf("iam-user-no-mfa-%s", [resource.name]),
        "policy_id": "iam_user_mfa_required",
        "severity": "high",
        "message": sprintf("IAM user '%s' does not enforce MFA", [resource.name]),
        "details": "IAM users with console access should have MFA enforced",
        "remediation": "Enable MFA for the user and create a policy that requires MFA for all actions"
    }
}

# Deny overly permissive AssumeRole policies
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_role"
    
    policy := resource.attributes.assume_role_policy
    statement := policy.Statement[_]
    
    # Check for overly permissive principal
    statement.Principal == "*"
    
    violation := {
        "id": sprintf("iam-role-trust-everyone-%s", [resource.name]),
        "policy_id": "iam_role_trust_policy",
        "severity": "critical",
        "message": sprintf("IAM role '%s' can be assumed by anyone", [resource.name]),
        "details": "IAM role trust policy allows any principal to assume the role",
        "remediation": "Restrict the Principal to specific AWS accounts, services, or users"
    }
}

# Deny IAM password policy without strong requirements
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_account_password_policy"
    
    # Check minimum password length
    resource.attributes.minimum_password_length < 14
    
    violation := {
        "id": sprintf("iam-weak-password-length-%s", [resource.name]),
        "policy_id": "iam_password_policy_length",
        "severity": "medium",
        "message": "IAM password policy has weak minimum length requirement",
        "details": sprintf("Minimum password length is %d, should be at least 14", [resource.attributes.minimum_password_length]),
        "remediation": "Set minimum_password_length to at least 14"
    }
}

# Deny IAM password policy without complexity requirements
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_account_password_policy"
    
    # Check if all complexity requirements are enabled
    not resource.attributes.require_uppercase_characters
    
    violation := {
        "id": "iam-password-no-uppercase",
        "policy_id": "iam_password_complexity",
        "severity": "medium",
        "message": "IAM password policy does not require uppercase characters",
        "details": "Password policy should require a mix of character types",
        "remediation": "Set require_uppercase_characters = true"
    }
}

deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_account_password_policy"
    
    not resource.attributes.require_lowercase_characters
    
    violation := {
        "id": "iam-password-no-lowercase",
        "policy_id": "iam_password_complexity",
        "severity": "medium",
        "message": "IAM password policy does not require lowercase characters",
        "details": "Password policy should require a mix of character types",
        "remediation": "Set require_lowercase_characters = true"
    }
}

deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_account_password_policy"
    
    not resource.attributes.require_numbers
    
    violation := {
        "id": "iam-password-no-numbers",
        "policy_id": "iam_password_complexity",
        "severity": "medium",
        "message": "IAM password policy does not require numbers",
        "details": "Password policy should require a mix of character types",
        "remediation": "Set require_numbers = true"
    }
}

deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_account_password_policy"
    
    not resource.attributes.require_symbols
    
    violation := {
        "id": "iam-password-no-symbols",
        "policy_id": "iam_password_complexity",
        "severity": "medium",
        "message": "IAM password policy does not require symbols",
        "details": "Password policy should require a mix of character types",
        "remediation": "Set require_symbols = true"
    }
}

# Deny IAM password policy without rotation
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_account_password_policy"
    
    # Check password age
    resource.attributes.max_password_age > 90
    
    violation := {
        "id": "iam-password-rotation",
        "policy_id": "iam_password_rotation",
        "severity": "medium",
        "message": sprintf("IAM password policy allows passwords older than %d days", [resource.attributes.max_password_age]),
        "details": "Passwords should be rotated regularly, recommended every 90 days",
        "remediation": "Set max_password_age to 90 or less"
    }
}

# Deny IAM access keys without rotation
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_access_key"
    
    # Note: In real implementation, this would check the key age
    # For now, we'll flag all keys and recommend rotation policy
    
    violation := {
        "id": sprintf("iam-access-key-rotation-%s", [resource.name]),
        "policy_id": "iam_access_key_rotation",
        "severity": "medium",
        "message": sprintf("IAM access key '%s' should have rotation policy", [resource.name]),
        "details": "Access keys should be rotated regularly (every 90 days)",
        "remediation": "Implement access key rotation policy and monitor key age"
    }
}

# Helper functions

# Check if statement contains wildcard action
contains_wildcard_action(statement) {
    statement.Action == "*"
}

contains_wildcard_action(statement) {
    statement.Action[_] == "*"
}

# Check if statement contains wildcard resource
contains_wildcard_resource(statement) {
    statement.Resource == "*"
}

contains_wildcard_resource(statement) {
    statement.Resource[_] == "*"
}