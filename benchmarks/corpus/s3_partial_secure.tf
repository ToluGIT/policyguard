# Benchmark fixture: a bucket that is secured on most dimensions (encryption and
# logging configured inline) but still has a public ACL. A realistic, common
# mistake: someone hardened the data-at-rest story but left the bucket public.
#
# SME judgment: exactly ONE finding is correct here — the public ACL. The
# encryption and logging dimensions are genuinely satisfied, so a correct policy
# set must NOT flag them. This fixture tests precision on the secured dimensions
# (no over-reporting) while still catching the one real issue.

resource "aws_s3_bucket" "partial" {
  bucket = "bench-partial-secure"
  acl    = "public-read" # -> s3_bucket_public_access (the only expected finding)

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  logging {
    target_bucket = "bench-log-bucket"
    target_prefix = "log/"
  }
}
