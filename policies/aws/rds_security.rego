package policyguard

import future.keywords.contains
import future.keywords.if

# Description: Comprehensive RDS security policies for AWS

# Deny RDS instances without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    not resource.attributes.storage_encrypted
    
    violation := {
        "id": sprintf("rds-no-encryption-%s", [resource.name]),
        "policy_id": "rds_encryption_required",
        "severity": "high",
        "message": sprintf("RDS instance '%s' does not have encryption at rest enabled", [resource.name]),
        "details": "RDS instances should have encryption enabled to protect data at rest",
        "remediation": "Set storage_encrypted = true and optionally specify kms_key_id"
    }
}

# Deny RDS instances with public access
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
        "remediation": "Set publicly_accessible = false and use VPN or bastion hosts for access"
    }
}

# Deny RDS instances without backup
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    resource.attributes.backup_retention_period == 0
    
    violation := {
        "id": sprintf("rds-no-backup-%s", [resource.name]),
        "policy_id": "rds_backup_required",
        "severity": "high",
        "message": sprintf("RDS instance '%s' has backups disabled", [resource.name]),
        "details": "RDS instances should have automated backups enabled",
        "remediation": "Set backup_retention_period to at least 7 days"
    }
}

# Deny RDS instances with short backup retention
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    resource.attributes.backup_retention_period > 0
    resource.attributes.backup_retention_period < 7
    
    violation := {
        "id": sprintf("rds-short-backup-%s", [resource.name]),
        "policy_id": "rds_backup_retention",
        "severity": "medium",
        "message": sprintf("RDS instance '%s' has backup retention of only %d days", [resource.name, resource.attributes.backup_retention_period]),
        "details": "RDS instances should retain backups for at least 7 days",
        "remediation": "Set backup_retention_period to at least 7 days"
    }
}

# Deny RDS instances without Multi-AZ for production
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    # Check if it's a production instance (by tags or name)
    resource.attributes.tags.Environment == "production"
    not resource.attributes.multi_az
    
    violation := {
        "id": sprintf("rds-no-multi-az-%s", [resource.name]),
        "policy_id": "rds_multi_az_production",
        "severity": "high",
        "message": sprintf("Production RDS instance '%s' does not have Multi-AZ enabled", [resource.name]),
        "details": "Production RDS instances should have Multi-AZ enabled for high availability",
        "remediation": "Set multi_az = true for production instances"
    }
}

# Deny RDS instances without deletion protection for production
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    resource.attributes.tags.Environment == "production"
    not resource.attributes.deletion_protection
    
    violation := {
        "id": sprintf("rds-no-deletion-protection-%s", [resource.name]),
        "policy_id": "rds_deletion_protection",
        "severity": "medium",
        "message": sprintf("Production RDS instance '%s' does not have deletion protection", [resource.name]),
        "details": "Production RDS instances should have deletion protection enabled",
        "remediation": "Set deletion_protection = true for production instances"
    }
}

# Deny RDS instances without IAM authentication
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    not resource.attributes.iam_database_authentication_enabled
    
    violation := {
        "id": sprintf("rds-no-iam-auth-%s", [resource.name]),
        "policy_id": "rds_iam_authentication",
        "severity": "medium",
        "message": sprintf("RDS instance '%s' does not have IAM authentication enabled", [resource.name]),
        "details": "IAM database authentication provides additional security for database access",
        "remediation": "Set iam_database_authentication_enabled = true"
    }
}

# Deny RDS instances without performance insights for production
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    resource.attributes.tags.Environment == "production"
    not resource.attributes.performance_insights_enabled
    
    violation := {
        "id": sprintf("rds-no-performance-insights-%s", [resource.name]),
        "policy_id": "rds_performance_insights",
        "severity": "low",
        "message": sprintf("Production RDS instance '%s' does not have Performance Insights enabled", [resource.name]),
        "details": "Performance Insights helps monitor database performance",
        "remediation": "Set performance_insights_enabled = true and optionally set retention period"
    }
}

# Deny RDS instances without log exports
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    not resource.attributes.enabled_cloudwatch_logs_exports
    
    violation := {
        "id": sprintf("rds-no-log-exports-%s", [resource.name]),
        "policy_id": "rds_cloudwatch_logs",
        "severity": "medium",
        "message": sprintf("RDS instance '%s' does not export logs to CloudWatch", [resource.name]),
        "details": "RDS logs should be exported to CloudWatch for monitoring and compliance",
        "remediation": "Set enabled_cloudwatch_logs_exports with appropriate log types for your engine"
    }
}

# Deny RDS instances with default parameter group
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    
    contains(resource.attributes.parameter_group_name, "default")
    
    violation := {
        "id": sprintf("rds-default-parameter-group-%s", [resource.name]),
        "policy_id": "rds_custom_parameter_group",
        "severity": "low",
        "message": sprintf("RDS instance '%s' uses default parameter group", [resource.name]),
        "details": "Custom parameter groups allow for security hardening and optimization",
        "remediation": "Create and use a custom parameter group with security-focused settings"
    }
}

# Deny RDS clusters without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_rds_cluster"
    
    not resource.attributes.storage_encrypted
    
    violation := {
        "id": sprintf("rds-cluster-no-encryption-%s", [resource.name]),
        "policy_id": "rds_cluster_encryption",
        "severity": "high",
        "message": sprintf("RDS cluster '%s' does not have encryption enabled", [resource.name]),
        "details": "RDS clusters should have encryption enabled for data at rest",
        "remediation": "Set storage_encrypted = true and optionally specify kms_key_id"
    }
}

# Deny RDS clusters without backup
deny[violation] {
    resource := input.resource
    resource.type == "aws_rds_cluster"
    
    resource.attributes.backup_retention_period == 0
    
    violation := {
        "id": sprintf("rds-cluster-no-backup-%s", [resource.name]),
        "policy_id": "rds_cluster_backup",
        "severity": "high",
        "message": sprintf("RDS cluster '%s' has backups disabled", [resource.name]),
        "details": "RDS clusters should have automated backups enabled",
        "remediation": "Set backup_retention_period to at least 7 days"
    }
}

# Deny DB snapshots without encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_snapshot"
    
    not resource.attributes.encrypted
    
    violation := {
        "id": sprintf("rds-snapshot-no-encryption-%s", [resource.name]),
        "policy_id": "rds_snapshot_encryption",
        "severity": "high",
        "message": sprintf("RDS snapshot '%s' is not encrypted", [resource.name]),
        "details": "RDS snapshots should be encrypted to protect data at rest",
        "remediation": "Enable encryption when creating snapshots"
    }
}

# Deny DB snapshots that are public
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_snapshot"
    
    attribute := resource.attributes.restore[_]
    attribute == "all"
    
    violation := {
        "id": sprintf("rds-snapshot-public-%s", [resource.name]),
        "policy_id": "rds_snapshot_not_public",
        "severity": "critical",
        "message": sprintf("RDS snapshot '%s' is publicly accessible", [resource.name]),
        "details": "RDS snapshots should never be publicly accessible",
        "remediation": "Remove public access from the snapshot"
    }
}