package policyguard

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny S3 buckets without server-side encryption.
#
# Encryption can be configured two ways:
#   1. Inline on aws_s3_bucket via server_side_encryption_configuration (older
#      provider style), or
#   2. A separate aws_s3_bucket_server_side_encryption_configuration resource
#      that references the bucket (AWS provider v4+ style).
# We only flag a bucket when NEITHER is present, so a bucket correctly secured
# the modern way is not a false positive.
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"

    not resource.attributes.server_side_encryption_configuration
    not has_sse_sibling(resource)

    violation := {
        "id": sprintf("s3-no-encryption-%s", [resource.name]),
        "policy_id": "s3_bucket_encryption",
        "severity": "high",
        "message": sprintf("S3 bucket '%s' does not have server-side encryption enabled", [resource.name]),
        "details": "S3 buckets should have server-side encryption enabled to protect data at rest, either inline or via an aws_s3_bucket_server_side_encryption_configuration resource",
        "remediation": "Add a server_side_encryption_configuration block, or an aws_s3_bucket_server_side_encryption_configuration resource referencing this bucket, using AES256 or aws:kms"
    }
}

# Deny S3 buckets with encryption but using deprecated settings
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"

    # Check for deprecated encryption settings
    resource.attributes.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm == "AES128"

    violation := {
        "id": sprintf("s3-weak-encryption-%s", [resource.name]),
        "policy_id": "s3_bucket_encryption",
        "severity": "medium",
        "message": sprintf("S3 bucket '%s' uses weak encryption algorithm", [resource.name]),
        "details": "AES128 is deprecated, use AES256 or aws:kms instead",
        "remediation": "Update sse_algorithm to 'AES256' or 'aws:kms'"
    }
}

# has_sse_sibling is true when a separate
# aws_s3_bucket_server_side_encryption_configuration resource references this
# bucket. The reference is matched against the bucket's resource address
# (e.g. "aws_s3_bucket.modern.id" references aws_s3_bucket "modern"). Matching is
# scoped to the same module so two modules that each name a bucket "this" do not
# cross-suppress each other (a bucket reference is local to its module).
has_sse_sibling(bucket) if {
    some sibling in input.all_resources
    sibling.type == "aws_s3_bucket_server_side_encryption_configuration"
    same_module(sibling, bucket)
    references_bucket(sibling.attributes.bucket, bucket.name)
}

# same_module reports whether two resources live in the same module context.
# Resources carry their module via the _module_name attribute (absent for
# root-module resources); two resources match when that value is equal (both
# absent counts as equal: the root module).
same_module(a, b) if {
    module_of(a) == module_of(b)
}

module_of(resource) := name if {
    name := resource.attributes._module_name
}

module_of(resource) := "" if {
    not resource.attributes._module_name
}

# references_bucket reports whether a sibling's `bucket` attribute points at the
# aws_s3_bucket named bucket_name. It matches the Terraform reference form
# "aws_s3_bucket.<name>.<attr>" (and a bare "aws_s3_bucket.<name>").
references_bucket(ref, bucket_name) if {
    is_string(ref)
    startswith(ref, sprintf("aws_s3_bucket.%s.", [bucket_name]))
}

references_bucket(ref, bucket_name) if {
    is_string(ref)
    ref == sprintf("aws_s3_bucket.%s", [bucket_name])
}
