package policyguard

import future.keywords.contains
import future.keywords.if

# Deny API Gateway REST APIs without HTTPS enforcement
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_rest_api"
    
    # Check if minimum_tls_version is not set or set to insecure version
    not resource.attributes.minimum_tls_version
    
    violation := {
        "id": sprintf("api-gateway-no-min-tls-%s", [resource.name]),
        "policy_id": "api_gateway_https_enforcement",
        "severity": "high",
        "message": sprintf("API Gateway REST API '%s' does not enforce minimum TLS version", [resource.name]),
        "details": "API Gateway should enforce a minimum TLS version (1.2 or higher) for security",
        "remediation": "Set minimum_tls_version to 'TLS_1_2' in the API Gateway REST API configuration"
    }
}

# Deny API Gateway REST APIs with weak TLS versions
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_rest_api"
    
    # Check if TLS version is too low
    resource.attributes.minimum_tls_version == "TLS_1_0"
    
    violation := {
        "id": sprintf("api-gateway-weak-tls-%s", [resource.name]),
        "policy_id": "api_gateway_https_enforcement",
        "severity": "high",
        "message": sprintf("API Gateway REST API '%s' uses weak TLS version 1.0", [resource.name]),
        "details": "TLS 1.0 is deprecated and vulnerable to attacks",
        "remediation": "Update minimum_tls_version to 'TLS_1_2' or 'TLS_1_3'"
    }
}

# Deny API Gateway stages without logging enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_stage"
    
    # Check if access logging is disabled
    not resource.attributes.access_log_settings
    
    violation := {
        "id": sprintf("api-gateway-stage-no-logging-%s", [resource.name]),
        "policy_id": "api_gateway_logging",
        "severity": "medium",
        "message": sprintf("API Gateway stage '%s' does not have access logging enabled", [resource.name]),
        "details": "API Gateway stages should have access logging enabled for monitoring and security auditing",
        "remediation": "Configure access_log_settings with destination_arn and format in the stage configuration"
    }
}

# Deny API Gateway stages without X-Ray tracing
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_stage"
    
    # Check if X-Ray tracing is disabled
    resource.attributes.xray_tracing_enabled == false
    
    violation := {
        "id": sprintf("api-gateway-stage-no-xray-%s", [resource.name]),
        "policy_id": "api_gateway_tracing",
        "severity": "low",
        "message": sprintf("API Gateway stage '%s' does not have X-Ray tracing enabled", [resource.name]),
        "details": "X-Ray tracing helps with performance monitoring and debugging",
        "remediation": "Set xray_tracing_enabled to true in the stage configuration"
    }
}

# Deny API Gateway methods without authentication
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_method"
    
    # Check if authorization is set to NONE
    resource.attributes.authorization == "NONE"
    
    # Skip OPTIONS methods (CORS preflight)
    resource.attributes.http_method != "OPTIONS"
    
    violation := {
        "id": sprintf("api-gateway-method-no-auth-%s", [resource.name]),
        "policy_id": "api_gateway_authentication",
        "severity": "critical",
        "message": sprintf("API Gateway method '%s' has no authentication", [resource.name]),
        "details": "API Gateway methods should require authentication unless specifically intended for public access",
        "remediation": "Set authorization to 'AWS_IAM', 'COGNITO_USER_POOLS', or implement a custom authorizer"
    }
}

# Deny API Gateway deployment without throttling
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_stage"
    
    # Check if throttling settings are missing
    not resource.attributes.throttle_settings
    
    violation := {
        "id": sprintf("api-gateway-stage-no-throttling-%s", [resource.name]),
        "policy_id": "api_gateway_throttling",
        "severity": "medium",
        "message": sprintf("API Gateway stage '%s' does not have throttling configured", [resource.name]),
        "details": "API Gateway stages should have throttling configured to prevent abuse and control costs",
        "remediation": "Configure throttle_settings with rate_limit and burst_limit in the stage"
    }
}

# Deny API Gateway without WAF association
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_stage"
    
    # This is a recommendation for production APIs
    # Check if it's likely a production stage
    contains(lower(resource.attributes.stage_name), "prod")
    
    # Look for associated WAF - this would need to be checked via aws_wafv2_web_acl_association
    # For now, we'll flag production stages that might need WAF
    not resource.attributes.web_acl_arn
    
    violation := {
        "id": sprintf("api-gateway-prod-no-waf-%s", [resource.name]),
        "policy_id": "api_gateway_waf_protection",
        "severity": "medium",
        "message": sprintf("API Gateway production stage '%s' should consider WAF protection", [resource.name]),
        "details": "Production API Gateway stages should be protected by AWS WAF for DDoS and application-layer attacks",
        "remediation": "Associate a WAF Web ACL with the API Gateway stage using aws_wafv2_web_acl_association"
    }
}

# Deny API Gateway with caching disabled for performance stages
deny[violation] {
    resource := input.resource
    resource.type == "aws_api_gateway_stage"
    
    # Check production or staging environments
    stage_name := lower(resource.attributes.stage_name)
    contains(stage_name, "prod")
    
    # Check if caching is disabled
    resource.attributes.cache_cluster_enabled == false
    
    violation := {
        "id": sprintf("api-gateway-prod-no-cache-%s", [resource.name]),
        "policy_id": "api_gateway_performance",
        "severity": "low",
        "message": sprintf("API Gateway production stage '%s' does not have caching enabled", [resource.name]),
        "details": "Production API Gateway stages should consider enabling caching for better performance and cost optimization",
        "remediation": "Set cache_cluster_enabled to true and configure appropriate cache_cluster_size"
    }
}