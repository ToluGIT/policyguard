package policyguard

import future.keywords.contains
import future.keywords.if

# Deny DynamoDB tables without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if encryption is missing or disabled
    not resource.attributes.server_side_encryption
    
    violation := {
        "id": sprintf("dynamodb-no-encryption-%s", [resource.name]),
        "policy_id": "dynamodb_encryption",
        "severity": "high",
        "message": sprintf("DynamoDB table '%s' does not have server-side encryption enabled", [resource.name]),
        "details": "DynamoDB tables should have server-side encryption enabled to protect sensitive data",
        "remediation": "Add server_side_encryption configuration block with enabled = true"
    }
}

# Deny DynamoDB tables using default AWS managed key (prefer customer managed keys)
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if using default AWS managed key instead of customer managed key
    resource.attributes.server_side_encryption.enabled == true
    not resource.attributes.server_side_encryption.kms_key_arn
    
    violation := {
        "id": sprintf("dynamodb-default-kms-%s", [resource.name]),
        "policy_id": "dynamodb_cmk_encryption",
        "severity": "medium",
        "message": sprintf("DynamoDB table '%s' uses default AWS managed key instead of customer managed key", [resource.name]),
        "details": "For better security control, DynamoDB tables should use customer managed KMS keys instead of default AWS managed keys",
        "remediation": "Specify a kms_key_arn in the server_side_encryption block"
    }
}

# Deny DynamoDB tables without point-in-time recovery
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if point-in-time recovery is disabled
    not resource.attributes.point_in_time_recovery
    
    violation := {
        "id": sprintf("dynamodb-no-pitr-%s", [resource.name]),
        "policy_id": "dynamodb_recovery",
        "severity": "medium",
        "message": sprintf("DynamoDB table '%s' does not have point-in-time recovery enabled", [resource.name]),
        "details": "Point-in-time recovery helps protect against accidental writes or deletes and aids in disaster recovery",
        "remediation": "Add point_in_time_recovery block with enabled = true"
    }
}

# Deny DynamoDB tables without any tags
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if required tags are missing
    not resource.attributes.tags
    
    violation := {
        "id": sprintf("dynamodb-no-tags-%s", [resource.name]),
        "policy_id": "dynamodb_tagging",
        "severity": "low",
        "message": sprintf("DynamoDB table '%s' has no resource tags", [resource.name]),
        "details": "DynamoDB tables should have proper resource tags for better organization and cost allocation",
        "remediation": "Add tags including Environment, Owner, and Purpose"
    }
}

# Deny DynamoDB tables with provisioned capacity but no autoscaling
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if using provisioned billing mode
    resource.attributes.billing_mode == "PROVISIONED"
    
    # Check if autoscaling is missing (simplified check - in real scenario would check for attached scaling policies)
    not_has_autoscaling_resource(resource.name)
    
    violation := {
        "id": sprintf("dynamodb-no-autoscaling-%s", [resource.name]),
        "policy_id": "dynamodb_autoscaling",
        "severity": "medium",
        "message": sprintf("DynamoDB table '%s' uses provisioned capacity without autoscaling", [resource.name]),
        "details": "Provisioned capacity DynamoDB tables should use autoscaling to handle traffic spikes and optimize costs",
        "remediation": "Either set billing_mode to PAY_PER_REQUEST or configure autoscaling via aws_appautoscaling_target and aws_appautoscaling_policy"
    }
}

# Helper function to simulate checking for autoscaling resources
# In a real scenario, you would check for related aws_appautoscaling_target resources
not_has_autoscaling_resource(table_name) = true {
    true  # Simplified - would need cross-resource analysis
}

# Deny DynamoDB tables with all attributes projected in secondary indexes
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check GSIs for ALL projection type
    gsi := resource.attributes.global_secondary_index[_]
    gsi.projection_type == "ALL"
    
    violation := {
        "id": sprintf("dynamodb-gsi-all-attributes-%s", [resource.name]),
        "policy_id": "dynamodb_projection_efficiency",
        "severity": "low",
        "message": sprintf("DynamoDB table '%s' has GSI with ALL attributes projected", [resource.name]),
        "details": "Projecting ALL attributes in GSIs increases storage costs. Consider using INCLUDE with specific attributes instead.",
        "remediation": "Change projection_type to INCLUDE and specify non-key attributes or use KEYS_ONLY if appropriate"
    }
}

# Deny DynamoDB tables without proper TTL for time-series data (detected by table name)
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if table name suggests time-series data
    name := lower(resource.attributes.name)
    time_series_indicators := ["log", "event", "metric", "timeseries", "history", "audit"]
    
    some i
    indicator := time_series_indicators[i]
    contains(name, indicator)
    
    # Check if TTL is not configured
    not resource.attributes.ttl
    
    violation := {
        "id": sprintf("dynamodb-timeseries-no-ttl-%s", [resource.name]),
        "policy_id": "dynamodb_ttl_management",
        "severity": "medium",
        "message": sprintf("Time-series DynamoDB table '%s' does not have TTL enabled", [resource.name]),
        "details": "Tables storing time-series data should have TTL enabled to automatically expire old data and control costs",
        "remediation": "Add ttl block with enabled = true and specify an attribute_name that holds timestamp values"
    }
}

# Check for DynamoDB tables without contributor insights (for performance monitoring)
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check for production tables without contributor insights
    tags := resource.attributes.tags
    tags.Environment == "production"
    
    # Check if contributor insights is disabled
    not_has_contributor_insights(resource.name)
    
    violation := {
        "id": sprintf("dynamodb-no-contributor-insights-%s", [resource.name]),
        "policy_id": "dynamodb_monitoring",
        "severity": "low",
        "message": sprintf("Production DynamoDB table '%s' doesn't have contributor insights enabled", [resource.name]),
        "details": "Production DynamoDB tables should have contributor insights enabled for better monitoring and troubleshooting",
        "remediation": "Enable contributor insights using aws_dynamodb_contributor_insights resource"
    }
}

# Helper function to check for contributor insights (simplified)
not_has_contributor_insights(table_name) = true {
    true  # Simplified - would need cross-resource analysis
}

# Check for DynamoDB tables with stream enabled but no lambda triggers (possible misconfiguration)
deny[violation] {
    resource := input.resource
    resource.type == "aws_dynamodb_table"
    
    # Check if streams are enabled
    resource.attributes.stream_enabled == true
    
    # Check if there's no associated event source mapping (simplified check)
    not_has_event_source_mapping(resource.name)
    
    violation := {
        "id": sprintf("dynamodb-stream-no-consumer-%s", [resource.name]),
        "policy_id": "dynamodb_stream_usage",
        "severity": "low",
        "message": sprintf("DynamoDB table '%s' has streams enabled but no apparent consumer", [resource.name]),
        "details": "DynamoDB streams without consumers may indicate misconfiguration and can lead to additional costs without benefits",
        "remediation": "Either disable streams if not needed or configure Lambda triggers via aws_lambda_event_source_mapping"
    }
}

# Helper function to check for event source mappings (simplified)
not_has_event_source_mapping(table_name) = true {
    true  # Simplified - would need cross-resource analysis
}

# Check for DynamoDB tables with overly permissive IAM policies
deny[violation] {
    resource := input.resource
    resource.type == "aws_iam_policy"
    
    # Check if policy contains DynamoDB actions with wildcard resources
    policy := json.unmarshal(resource.attributes.policy)
    statement := policy.Statement[_]
    
    # Check for DynamoDB actions
    contains(statement.Action, "dynamodb:")
    
    # Check for wildcard resources
    statement.Resource == "*"
    
    violation := {
        "id": sprintf("iam-dynamodb-wildcard-%s", [resource.name]),
        "policy_id": "dynamodb_iam_security",
        "severity": "high",
        "message": sprintf("IAM policy '%s' grants DynamoDB access with wildcard resources", [resource.name]),
        "details": "IAM policies should follow least privilege principle and specify exact DynamoDB resources rather than using wildcards",
        "remediation": "Replace '*' with specific DynamoDB table ARNs"
    }
}