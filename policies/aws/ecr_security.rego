package policyguard

import future.keywords.contains
import future.keywords.if

# Deny ECR repositories without image scanning enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # Check if image scanning is disabled
    not resource.attributes.image_scanning_configuration.scan_on_push
    
    violation := {
        "id": sprintf("ecr-no-scan-on-push-%s", [resource.name]),
        "policy_id": "ecr_vulnerability_scanning",
        "severity": "high",
        "message": sprintf("ECR repository '%s' does not have scan on push enabled", [resource.name]),
        "details": "ECR repositories should have vulnerability scanning enabled to detect security issues in container images",
        "remediation": "Configure image_scanning_configuration with scan_on_push = true"
    }
}

# Deny ECR repositories without lifecycle policies
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # Note: aws_ecr_lifecycle_policy is a separate resource, so this is a recommendation
    # We can't directly check for its existence, but we can flag repositories without lifecycle management
    
    violation := {
        "id": sprintf("ecr-no-lifecycle-policy-%s", [resource.name]),
        "policy_id": "ecr_lifecycle_management",
        "severity": "medium",
        "message": sprintf("ECR repository '%s' should have a lifecycle policy configured", [resource.name]),
        "details": "ECR repositories should have lifecycle policies to manage image retention and reduce storage costs",
        "remediation": "Create an aws_ecr_lifecycle_policy resource to manage image lifecycle"
    }
}

# Deny ECR repositories that are mutable (allow image overwrites)
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # Check if image mutability is enabled (MUTABLE)
    resource.attributes.image_tag_mutability == "MUTABLE"
    
    violation := {
        "id": sprintf("ecr-mutable-tags-%s", [resource.name]),
        "policy_id": "ecr_immutable_tags",
        "severity": "medium",
        "message": sprintf("ECR repository '%s' allows mutable image tags", [resource.name]),
        "details": "ECR repositories should use immutable tags to prevent accidental overwrites and ensure reproducible deployments",
        "remediation": "Set image_tag_mutability to 'IMMUTABLE'"
    }
}

# Deny ECR repositories without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # Check if encryption is not configured or set to AES256 (should use KMS)
    not resource.attributes.encryption_configuration
    
    violation := {
        "id": sprintf("ecr-no-encryption-%s", [resource.name]),
        "policy_id": "ecr_encryption",
        "severity": "high",
        "message": sprintf("ECR repository '%s' does not have encryption configured", [resource.name]),
        "details": "ECR repositories should use KMS encryption for enhanced security of container images",
        "remediation": "Configure encryption_configuration with encryption_type 'KMS' and a kms_key"
    }
}

# Deny ECR repositories using AES256 instead of KMS encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # Check if using AES256 instead of KMS
    resource.attributes.encryption_configuration.encryption_type == "AES256"
    
    violation := {
        "id": sprintf("ecr-aes256-encryption-%s", [resource.name]),
        "policy_id": "ecr_kms_encryption",
        "severity": "medium",
        "message": sprintf("ECR repository '%s' uses AES256 encryption instead of KMS", [resource.name]),
        "details": "For enhanced security and key management, consider using KMS encryption instead of AES256",
        "remediation": "Update encryption_configuration to use encryption_type 'KMS' with a customer-managed key"
    }
}

# Check ECR repository policies for public access
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository_policy"
    
    # Parse the policy to check for public access - this is a simplified check
    # In a real implementation, you'd want to parse the JSON policy more thoroughly
    contains(resource.attributes.policy, "\"Principal\": \"*\"")
    
    violation := {
        "id": sprintf("ecr-policy-public-access-%s", [resource.name]),
        "policy_id": "ecr_public_access",
        "severity": "critical",
        "message": sprintf("ECR repository policy '%s' allows public access", [resource.name]),
        "details": "ECR repository policies should not allow public access unless specifically intended for public images",
        "remediation": "Review and restrict the repository policy to specific AWS accounts or IAM principals"
    }
}

# Check for ECR repositories without explicit policies (relies on AWS account policies)
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # This is more of a best practice recommendation
    # Production repositories should have explicit access policies
    
    violation := {
        "id": sprintf("ecr-no-explicit-policy-%s", [resource.name]),
        "policy_id": "ecr_access_control",
        "severity": "low",
        "message": sprintf("ECR repository '%s' should have an explicit repository policy", [resource.name]),
        "details": "ECR repositories should have explicit access policies for better security control",
        "remediation": "Create an aws_ecr_repository_policy to explicitly control access to this repository"
    }
}

# Warn about ECR repositories without proper tagging
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_repository"
    
    # Check if repository lacks proper tagging
    not resource.attributes.tags.Environment
    
    violation := {
        "id": sprintf("ecr-no-environment-tag-%s", [resource.name]),
        "policy_id": "ecr_tagging",
        "severity": "low",
        "message": sprintf("ECR repository '%s' lacks Environment tag", [resource.name]),
        "details": "ECR repositories should be properly tagged for resource management and cost allocation",
        "remediation": "Add tags including Environment, Project, and Owner for better resource management"
    }
}

# Check ECR lifecycle policies for security best practices
deny[violation] {
    resource := input.resource
    resource.type == "aws_ecr_lifecycle_policy"
    
    # Parse lifecycle policy to ensure it's not too permissive
    # This is a simplified check - in practice you'd parse the JSON policy
    contains(resource.attributes.policy, "\"countType\": \"sinceImagePushed\"")
    contains(resource.attributes.policy, "\"countNumber\": 1000")
    
    violation := {
        "id": sprintf("ecr-lifecycle-too-permissive-%s", [resource.name]),
        "policy_id": "ecr_lifecycle_security",
        "severity": "medium",
        "message": sprintf("ECR lifecycle policy '%s' may be too permissive", [resource.name]),
        "details": "ECR lifecycle policies should balance retention needs with security by not keeping too many old images",
        "remediation": "Review lifecycle policy to ensure appropriate image retention limits"
    }
}