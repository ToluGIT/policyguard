# Benchmark fixture: S3 buckets with explicit, unambiguous misconfigurations.
# Every credential/value here is synthetic. Ground truth is in labels.json.
#
# SME judgment: a bucket that is public-read, unencrypted, and unlogged is
# insecure by any reasonable standard. These are the clear true positives.

resource "aws_s3_bucket" "public_unencrypted" {
  bucket = "bench-public-unencrypted"
  acl    = "public-read-write"
  # no server_side_encryption_configuration  -> s3_bucket_encryption
  # no logging                                -> s3_bucket_logging
  # public-read-write acl                     -> s3_bucket_public_access
}

resource "aws_s3_bucket_public_access_block" "wide_open" {
  bucket                  = aws_s3_bucket.public_unencrypted.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
  # all four false -> s3_bucket_public_access
}
