package policyguard

import future.keywords.contains
import future.keywords.if

# Deny CloudTrail without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if KMS key is not configured for encryption
    not resource.attributes.kms_key_id
    
    violation := {
        "id": sprintf("cloudtrail-no-encryption-%s", [resource.name]),
        "policy_id": "cloudtrail_encryption",
        "severity": "high",
        "message": sprintf("CloudTrail '%s' does not have log encryption enabled", [resource.name]),
        "details": "CloudTrail logs should be encrypted at rest using KMS to protect sensitive audit data",
        "remediation": "Configure kms_key_id with a KMS key ARN for CloudTrail log encryption"
    }
}

# Deny CloudTrail that is not multi-region
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if multi-region is disabled
    resource.attributes.is_multi_region_trail == false
    
    violation := {
        "id": sprintf("cloudtrail-single-region-%s", [resource.name]),
        "policy_id": "cloudtrail_multi_region",
        "severity": "high",
        "message": sprintf("CloudTrail '%s' is not configured as multi-region trail", [resource.name]),
        "details": "CloudTrail should be configured as multi-region to capture events from all AWS regions",
        "remediation": "Set is_multi_region_trail to true"
    }
}

# Deny CloudTrail without global service events
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if global service events are disabled
    resource.attributes.include_global_service_events == false
    
    violation := {
        "id": sprintf("cloudtrail-no-global-events-%s", [resource.name]),
        "policy_id": "cloudtrail_global_events",
        "severity": "medium",
        "message": sprintf("CloudTrail '%s' does not include global service events", [resource.name]),
        "details": "CloudTrail should include global service events (IAM, STS, CloudFront, etc.) for complete audit coverage",
        "remediation": "Set include_global_service_events to true"
    }
}

# Deny CloudTrail with logging disabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if logging is explicitly disabled
    resource.attributes.enable_logging == false
    
    violation := {
        "id": sprintf("cloudtrail-logging-disabled-%s", [resource.name]),
        "policy_id": "cloudtrail_logging_enabled",
        "severity": "critical",
        "message": sprintf("CloudTrail '%s' has logging disabled", [resource.name]),
        "details": "CloudTrail logging must be enabled to maintain audit trail and compliance",
        "remediation": "Set enable_logging to true or remove the parameter (defaults to true)"
    }
}

# Deny CloudTrail without log file validation
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if log file validation is disabled
    resource.attributes.enable_log_file_validation == false
    
    violation := {
        "id": sprintf("cloudtrail-no-validation-%s", [resource.name]),
        "policy_id": "cloudtrail_log_validation",
        "severity": "medium",
        "message": sprintf("CloudTrail '%s' does not have log file validation enabled", [resource.name]),
        "details": "Log file validation should be enabled to detect tampering of CloudTrail logs",
        "remediation": "Set enable_log_file_validation to true"
    }
}

# Deny CloudTrail S3 bucket without proper security
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # This checks if there's an S3 bucket configured but we can't verify its security
    # Users should ensure the S3 bucket has proper policies
    resource.attributes.s3_bucket_name
    
    # Flag for manual verification since we can't cross-reference other resources in this policy
    not resource.attributes.s3_key_prefix
    
    violation := {
        "id": sprintf("cloudtrail-s3-no-prefix-%s", [resource.name]),
        "policy_id": "cloudtrail_s3_organization",
        "severity": "low",
        "message": sprintf("CloudTrail '%s' does not specify S3 key prefix", [resource.name]),
        "details": "Using S3 key prefix helps organize CloudTrail logs and can improve security policies",
        "remediation": "Configure s3_key_prefix to organize CloudTrail logs in S3 bucket"
    }
}

# Deny CloudTrail without event selectors for data events
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if event selectors are missing (no data events tracking)
    not resource.attributes.event_selector
    
    violation := {
        "id": sprintf("cloudtrail-no-data-events-%s", [resource.name]),
        "policy_id": "cloudtrail_data_events",
        "severity": "medium",
        "message": sprintf("CloudTrail '%s' has no data event logging configured", [resource.name]),
        "details": "Consider configuring data event logging for S3 objects and Lambda functions for enhanced security monitoring",
        "remediation": "Add event_selector blocks to track data events for S3 buckets and Lambda functions"
    }
}

# Deny CloudTrail without insight selectors
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if insight selectors are missing
    not resource.attributes.insight_selector
    
    violation := {
        "id": sprintf("cloudtrail-no-insights-%s", [resource.name]),
        "policy_id": "cloudtrail_insights",
        "severity": "low",
        "message": sprintf("CloudTrail '%s' does not have CloudTrail Insights enabled", [resource.name]),
        "details": "CloudTrail Insights can help identify unusual operational patterns and potential security issues",
        "remediation": "Add insight_selector block with insight_type 'ApiCallRateInsight' to enable CloudTrail Insights"
    }
}

# Warn about CloudTrail without SNS notifications
deny[violation] {
    resource := input.resource
    resource.type == "aws_cloudtrail"
    
    # Check if SNS topic is not configured
    not resource.attributes.sns_topic_name
    
    violation := {
        "id": sprintf("cloudtrail-no-sns-%s", [resource.name]),
        "policy_id": "cloudtrail_notifications",
        "severity": "low",
        "message": sprintf("CloudTrail '%s' does not have SNS notifications configured", [resource.name]),
        "details": "SNS notifications can provide real-time alerts for CloudTrail log delivery",
        "remediation": "Configure sns_topic_name to receive notifications about log file delivery"
    }
}