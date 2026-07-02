# Benchmark fixture: a bucket secured using the MODERN split-resource pattern
# (AWS Terraform provider v4+), where encryption, logging, and public-access
# settings live in SEPARATE resources rather than inline on aws_s3_bucket.
#
# SME judgment: this bucket IS correctly secured. A knowledgeable reviewer
# would NOT flag it. Ground truth therefore lists ZERO expected violations.
#
# PolicyGuard's current single-resource policies only inspect inline attributes
# on aws_s3_bucket, so they cannot see the sibling resources and will flag this
# bucket for missing encryption and logging. Those findings are FALSE POSITIVES
# and are expected to lower measured precision. This fixture exists precisely to
# make that provider-schema-drift limitation visible and tracked, not hidden.

resource "aws_s3_bucket" "modern" {
  bucket = "bench-modern-split"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "modern" {
  bucket = aws_s3_bucket.modern.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_logging" "modern" {
  bucket        = aws_s3_bucket.modern.id
  target_bucket = "bench-log-bucket"
  target_prefix = "log/"
}

resource "aws_s3_bucket_public_access_block" "modern" {
  bucket                  = aws_s3_bucket.modern.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
