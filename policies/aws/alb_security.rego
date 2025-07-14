package policyguard

import future.keywords.contains
import future.keywords.if

# Deny ALB without HTTPS listener
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb"
    
    # Check if it's an application load balancer
    resource.attributes.load_balancer_type == "application"
    
    violation := {
        "id": sprintf("alb-needs-https-listener-%s", [resource.name]),
        "policy_id": "alb_https_listener",
        "severity": "high",
        "message": sprintf("Application Load Balancer '%s' should have HTTPS listeners configured", [resource.name]),
        "details": "ALB should use HTTPS listeners for secure communication. This requires separate aws_lb_listener resources.",
        "remediation": "Create aws_lb_listener resources with protocol 'HTTPS' and valid SSL certificates"
    }
}

# Deny ALB listeners using HTTP without redirect to HTTPS
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb_listener"
    
    # Check if using HTTP protocol
    resource.attributes.protocol == "HTTP"
    
    # Check if default action is not redirect to HTTPS
    not resource.attributes.default_action.redirect
    
    violation := {
        "id": sprintf("alb-listener-http-no-redirect-%s", [resource.name]),
        "policy_id": "alb_http_redirect",
        "severity": "high",
        "message": sprintf("ALB listener '%s' uses HTTP without redirecting to HTTPS", [resource.name]),
        "details": "HTTP listeners should redirect traffic to HTTPS for security",
        "remediation": "Configure default_action with redirect to HTTPS or change protocol to HTTPS"
    }
}

# Deny ALB HTTPS listeners with weak SSL policies
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb_listener"
    
    # Check if using HTTPS protocol
    resource.attributes.protocol == "HTTPS"
    
    # Check for weak SSL policy
    weak_policies := [
        "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01"
    ]
    
    resource.attributes.ssl_policy == weak_policies[_]
    
    violation := {
        "id": sprintf("alb-listener-weak-ssl-%s", [resource.name]),
        "policy_id": "alb_ssl_policy",
        "severity": "high",
        "message": sprintf("ALB HTTPS listener '%s' uses weak SSL policy", [resource.name]),
        "details": "ALB HTTPS listeners should use strong SSL policies that support TLS 1.2 or higher",
        "remediation": "Update ssl_policy to 'ELBSecurityPolicy-TLS-1-2-2017-01' or newer"
    }
}

# Deny ALB without access logging enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb"
    
    # Check if it's an application load balancer
    resource.attributes.load_balancer_type == "application"
    
    # Check if access logs are disabled
    resource.attributes.access_logs.enabled == false
    
    violation := {
        "id": sprintf("alb-no-access-logs-%s", [resource.name]),
        "policy_id": "alb_access_logging",
        "severity": "medium",
        "message": sprintf("Application Load Balancer '%s' does not have access logging enabled", [resource.name]),
        "details": "ALB access logs provide valuable information for security monitoring and troubleshooting",
        "remediation": "Enable access_logs with enabled = true and specify an S3 bucket"
    }
}

# Deny ALB that is internet-facing without proper security groups
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb"
    
    # Check if it's internet-facing
    resource.attributes.internal == false
    
    # This is a recommendation - we can't verify security group rules from here
    # but we can flag internet-facing ALBs for review
    not resource.attributes.security_groups
    
    violation := {
        "id": sprintf("alb-internet-facing-no-sg-%s", [resource.name]),
        "policy_id": "alb_security_groups",
        "severity": "high",
        "message": sprintf("Internet-facing ALB '%s' should have security groups configured", [resource.name]),
        "details": "Internet-facing ALBs should have properly configured security groups to control access",
        "remediation": "Configure security_groups with restrictive inbound rules for the ALB"
    }
}

# Deny ALB without deletion protection in production
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb"
    
    # Check if it might be a production ALB (based on name or tags)
    alb_name := lower(resource.name)
    contains(alb_name, "prod")
    
    # Check if deletion protection is disabled
    resource.attributes.enable_deletion_protection == false
    
    violation := {
        "id": sprintf("alb-prod-no-deletion-protection-%s", [resource.name]),
        "policy_id": "alb_deletion_protection",
        "severity": "medium",
        "message": sprintf("Production ALB '%s' should have deletion protection enabled", [resource.name]),
        "details": "Production ALBs should have deletion protection to prevent accidental deletion",
        "remediation": "Set enable_deletion_protection to true for production ALBs"
    }
}

# Deny ALB target groups without health checks properly configured
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb_target_group"
    
    # Check for insufficient health check configuration
    resource.attributes.health_check_enabled == false
    
    violation := {
        "id": sprintf("alb-tg-no-health-check-%s", [resource.name]),
        "policy_id": "alb_health_checks",
        "severity": "medium",
        "message": sprintf("ALB target group '%s' has health checks disabled", [resource.name]),
        "details": "ALB target groups should have health checks enabled to ensure traffic is only sent to healthy targets",
        "remediation": "Set health_check_enabled to true and configure appropriate health check parameters"
    }
}

# Deny ALB target groups with weak health check configuration
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb_target_group"
    
    # Check for weak health check intervals
    resource.attributes.health_check_interval_seconds > 60
    
    violation := {
        "id": sprintf("alb-tg-slow-health-check-%s", [resource.name]),
        "policy_id": "alb_health_check_timing",
        "severity": "low",
        "message": sprintf("ALB target group '%s' has slow health check interval", [resource.name]),
        "details": "Health check intervals should be frequent enough to quickly detect unhealthy targets",
        "remediation": "Consider reducing health_check_interval_seconds to 30 seconds or less"
    }
}

# Warn about ALB without WAF protection
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb"
    
    # Check if it's an internet-facing ALB
    resource.attributes.internal == false
    
    # This is a recommendation for internet-facing ALBs
    # WAF association would be done via aws_wafv2_web_acl_association
    
    violation := {
        "id": sprintf("alb-internet-facing-no-waf-%s", [resource.name]),
        "policy_id": "alb_waf_protection",
        "severity": "medium",
        "message": sprintf("Internet-facing ALB '%s' should consider WAF protection", [resource.name]),
        "details": "Internet-facing ALBs should be protected by AWS WAF for application-layer security",
        "remediation": "Associate a WAF Web ACL using aws_wafv2_web_acl_association resource"
    }
}

# Check for ALB with HTTP/2 disabled (performance and security)
deny[violation] {
    resource := input.resource
    resource.type == "aws_lb"
    
    # Check if HTTP/2 is explicitly disabled
    resource.attributes.enable_http2 == false
    
    violation := {
        "id": sprintf("alb-http2-disabled-%s", [resource.name]),
        "policy_id": "alb_http2_enabled",
        "severity": "low",
        "message": sprintf("ALB '%s' has HTTP/2 disabled", [resource.name]),
        "details": "HTTP/2 provides performance and security benefits and should be enabled unless there's a specific reason to disable it",
        "remediation": "Set enable_http2 to true or remove the parameter (defaults to true)"
    }
}