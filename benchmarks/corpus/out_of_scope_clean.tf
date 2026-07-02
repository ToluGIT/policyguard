# Benchmark fixture: resources from services NOT in the core-security scope, in
# reasonable configurations. This is a true-negative diversity check: the core
# policy set must not spuriously flag these against any core policy. (Out-of-
# scope policies like tagging may still comment on them; the benchmark ignores
# those by design — only core_policies are scored.)
#
# SME judgment: zero core-set findings expected.

resource "aws_sns_topic" "events" {
  name              = "bench-events"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sqs_queue" "jobs" {
  name                      = "bench-jobs"
  kms_master_key_id         = "alias/aws/sqs"
  message_retention_seconds = 345600
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/bench/app"
  retention_in_days = 90
}
