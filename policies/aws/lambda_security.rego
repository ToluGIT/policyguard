package policyguard

import future.keywords.contains
import future.keywords.if

# Description: Security policies for AWS Lambda functions

# Deny Lambda functions without encryption for environment variables
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if environment variables exist but KMS key is not configured
    resource.attributes.environment
    not resource.attributes.kms_key_arn
    
    violation := {
        "id": sprintf("lambda-env-vars-no-encryption-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-encrypt-env-vars",
        "severity": "high",
        "message": sprintf("Lambda function '%s' has environment variables without KMS encryption", [resource.name]),
        "details": "Lambda functions with environment variables should use KMS encryption to protect sensitive data",
        "remediation": "Set kms_key_arn to encrypt environment variables at rest",
        "location": resource.location
    }
}

# Deny Lambda functions with sensitive data in environment variables
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check for common patterns of sensitive data in env var names
    env_vars := resource.attributes.environment[0].variables
    sensitive_patterns := ["password", "secret", "key", "token", "credential", "private"]
    
    env_var_name := env_vars[_]
    pattern := sensitive_patterns[_]
    contains(lower(env_var_name), pattern)
    
    violation := {
        "id": sprintf("lambda-sensitive-env-vars-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-no-secrets-in-env",
        "severity": "critical",
        "message": sprintf("Lambda function '%s' may contain sensitive data in environment variables", [resource.name]),
        "details": "Sensitive data like passwords and API keys should not be stored in environment variables",
        "remediation": "Use AWS Secrets Manager or SSM Parameter Store for sensitive data",
        "location": resource.location
    }
}

# Deny Lambda functions without VPC configuration for production
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if VPC configuration is missing
    not resource.attributes.vpc_config
    
    # Check if it's a production function
    resource.attributes.tags.Environment == "production"
    
    violation := {
        "id": sprintf("lambda-no-vpc-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-vpc-required",
        "severity": "medium",
        "message": sprintf("Production Lambda function '%s' is not in a VPC", [resource.name]),
        "details": "Production Lambda functions should run inside a VPC for network isolation",
        "remediation": "Configure vpc_config with appropriate subnet_ids and security_group_ids",
        "location": resource.location
    }
}

# Deny Lambda functions with excessive timeout
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if timeout is more than 5 minutes (300 seconds)
    resource.attributes.timeout > 300
    
    violation := {
        "id": sprintf("lambda-excessive-timeout-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-timeout-limit",
        "severity": "medium",
        "message": sprintf("Lambda function '%s' has timeout of %d seconds", [resource.name, resource.attributes.timeout]),
        "details": "Lambda functions should have reasonable timeouts to prevent runaway costs and resource usage",
        "remediation": "Reduce timeout to the minimum required for the function",
        "location": resource.location
    }
}

# Deny Lambda functions without X-Ray tracing
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if X-Ray tracing is not enabled
    not resource.attributes.tracing_config
    
    violation := {
        "id": sprintf("lambda-no-xray-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-xray-tracing",
        "severity": "low",
        "message": sprintf("Lambda function '%s' does not have X-Ray tracing enabled", [resource.name]),
        "details": "X-Ray tracing helps with debugging and performance monitoring",
        "remediation": "Set tracing_config with mode = 'Active' or 'PassThrough'",
        "location": resource.location
    }
}

# Deny Lambda functions with reserved concurrent executions set too high
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if reserved concurrent executions is unreasonably high
    resource.attributes.reserved_concurrent_executions > 1000
    
    violation := {
        "id": sprintf("lambda-high-concurrency-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-concurrency-limit",
        "severity": "medium",
        "message": sprintf("Lambda function '%s' has very high reserved concurrency: %d", [resource.name, resource.attributes.reserved_concurrent_executions]),
        "details": "Excessive reserved concurrency can impact other functions and increase costs",
        "remediation": "Set reserved_concurrent_executions to a reasonable value based on actual needs",
        "location": resource.location
    }
}

# Deny Lambda functions without dead letter queue configuration
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if dead letter config is missing
    not resource.attributes.dead_letter_config
    
    violation := {
        "id": sprintf("lambda-no-dlq-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-dlq-required",
        "severity": "medium",
        "message": sprintf("Lambda function '%s' does not have a dead letter queue configured", [resource.name]),
        "details": "Dead letter queues help handle failed Lambda invocations",
        "remediation": "Configure dead_letter_config with an SQS queue or SNS topic",
        "location": resource.location
    }
}

# Deny Lambda functions with outdated runtime
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check for deprecated or soon-to-be-deprecated runtimes
    deprecated_runtimes := [
        "python2.7", "python3.6", "python3.7",
        "nodejs10.x", "nodejs12.x", "nodejs14.x",
        "ruby2.5", "ruby2.7",
        "dotnetcore2.1", "dotnetcore3.1",
        "java8"
    ]
    
    resource.attributes.runtime == deprecated_runtimes[_]
    
    violation := {
        "id": sprintf("lambda-deprecated-runtime-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-supported-runtime",
        "severity": "high",
        "message": sprintf("Lambda function '%s' uses deprecated runtime: %s", [resource.name, resource.attributes.runtime]),
        "details": "Lambda functions should use supported runtime versions for security updates",
        "remediation": "Update to a supported runtime version",
        "location": resource.location
    }
}

# Deny Lambda layers without version pinning
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if layers are specified without version
    layer := resource.attributes.layers[_]
    not contains(layer, ":")
    
    violation := {
        "id": sprintf("lambda-layer-no-version-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-layer-version",
        "severity": "medium",
        "message": sprintf("Lambda function '%s' uses layers without version pinning", [resource.name]),
        "details": "Lambda layers should specify exact versions to ensure consistency",
        "remediation": "Use full layer ARN with version number",
        "location": resource.location
    }
}

# Deny Lambda functions without CloudWatch Logs retention
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Note: This would ideally check the associated CloudWatch log group
    # For now, we flag all functions and recommend setting retention
    
    violation := {
        "id": sprintf("lambda-no-log-retention-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-log-retention",
        "severity": "low",
        "message": sprintf("Lambda function '%s' should have CloudWatch Logs retention configured", [resource.name]),
        "details": "CloudWatch Logs should have retention policies to manage storage costs",
        "remediation": "Create aws_cloudwatch_log_group with retention_in_days set",
        "location": resource.location
    }
}

# Deny Lambda functions with public access
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_permission"
    
    # Check if principal is wildcard (public access)
    resource.attributes.principal == "*"
    
    violation := {
        "id": sprintf("lambda-public-access-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-no-public-access",
        "severity": "critical",
        "message": sprintf("Lambda function permission '%s' allows public access", [resource.name]),
        "details": "Lambda functions should not be publicly accessible",
        "remediation": "Restrict principal to specific AWS services or accounts",
        "location": resource.location
    }
}

# Deny Lambda functions without proper IAM role boundaries
deny[violation] {
    resource := input.resource
    resource.type == "aws_lambda_function"
    
    # Check if the function name suggests high privilege but no specific controls
    high_privilege_patterns := ["admin", "root", "privileged", "unrestricted"]
    pattern := high_privilege_patterns[_]
    contains(lower(resource.attributes.function_name), pattern)
    
    violation := {
        "id": sprintf("lambda-high-privilege-name-%s", [resource.name]),
        "resource_id": resource.id,
        "policy_id": "lambda-least-privilege",
        "severity": "medium",
        "message": sprintf("Lambda function '%s' name suggests high privileges", [resource.name]),
        "details": "Lambda functions should follow least privilege principle",
        "remediation": "Review IAM role permissions and ensure least privilege access",
        "location": resource.location
    }
}