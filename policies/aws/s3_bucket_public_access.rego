package policyguard

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny S3 buckets with public-read or public-read-write ACL
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    
    acl := resource.attributes.acl
    {"public-read", "public-read-write"}[acl]
    
    violation := {
        "id": sprintf("s3-public-acl-%s", [resource.name]),
        "policy_id": "s3_bucket_public_access",
        "severity": "critical",
        "message": sprintf("S3 bucket '%s' has public ACL '%s'", [resource.name, acl]),
        "details": "S3 buckets should not allow public access through ACLs",
        "remediation": "Set acl to 'private' and use bucket policies for controlled access"
    }
}

# Deny S3 bucket public access block with public access allowed
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket_public_access_block"
    
    # Check if any public access is allowed
    public_access_allowed := [
        resource.attributes.block_public_acls == false,
        resource.attributes.block_public_policy == false,
        resource.attributes.ignore_public_acls == false,
        resource.attributes.restrict_public_buckets == false
    ]
    
    public_access_allowed[_] == true
    
    violation := {
        "id": sprintf("s3-public-access-block-%s", [resource.name]),
        "policy_id": "s3_bucket_public_access",
        "severity": "high",
        "message": sprintf("S3 bucket public access block '%s' allows public access", [resource.name]),
        "details": "All public access block settings should be set to true",
        "remediation": "Set all public access block attributes to true"
    }
}

# Deny S3 buckets without logging enabled.
#
# Logging may be inline on aws_s3_bucket (logging block) or a separate
# aws_s3_bucket_logging resource (AWS provider v4+). Only flag when neither is
# present so a bucket logged the modern way is not a false positive.
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"

    not resource.attributes.logging
    not has_logging_sibling(resource)

    violation := {
        "id": sprintf("s3-no-logging-%s", [resource.name]),
        "policy_id": "s3_bucket_logging",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' does not have access logging enabled", [resource.name]),
        "details": "S3 bucket access logging helps with security auditing and compliance",
        "remediation": "Add a logging configuration block, or an aws_s3_bucket_logging resource referencing this bucket, with target_bucket and target_prefix"
    }
}

# has_logging_sibling is true when a separate aws_s3_bucket_logging resource
# references this bucket, scoped to the same module (see same_module in
# s3_bucket_encryption.rego — same package) so identically-named buckets in
# different modules do not cross-suppress.
has_logging_sibling(bucket) if {
    some sibling in input.all_resources
    sibling.type == "aws_s3_bucket_logging"
    same_module(sibling, bucket)
    s3_references_bucket(sibling.attributes.bucket, bucket.name)
}

# s3_references_bucket reports whether a sibling's `bucket` attribute points at
# the aws_s3_bucket named bucket_name (Terraform reference form
# "aws_s3_bucket.<name>.<attr>" or a bare "aws_s3_bucket.<name>").
s3_references_bucket(ref, bucket_name) if {
    is_string(ref)
    startswith(ref, sprintf("aws_s3_bucket.%s.", [bucket_name]))
}

s3_references_bucket(ref, bucket_name) if {
    is_string(ref)
    ref == sprintf("aws_s3_bucket.%s", [bucket_name])
}