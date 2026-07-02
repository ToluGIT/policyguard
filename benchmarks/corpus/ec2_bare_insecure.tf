# Benchmark fixture: an EC2 instance that sets NO security attributes.
#
# SME judgment: by AWS defaults, an instance with no metadata_options defaults
# to IMDSv1 being allowed (http_tokens "optional"), which is insecure. A
# thorough policy set SHOULD flag this for IMDSv2 not being enforced. Ground
# truth therefore lists ec2_instance_imdsv2 as an expected violation.
#
# PolicyGuard's ec2_instance_imdsv2 rule tests `http_tokens != "required"`,
# which does not fire when metadata_options is absent entirely. This instance
# is therefore expected to be MISSED — a FALSE NEGATIVE that lowers measured
# recall. The fixture exists to keep that absence-vs-explicit gap measured.
#
# We do NOT claim the missing root_block_device or public IP as expected
# findings: those policies test `== false` / `== true` and an omitted block is
# genuinely ambiguous (the instance may inherit a secure AMI default), so an
# SME would not assert a violation there. Only the IMDSv2 default is clear-cut.

resource "aws_instance" "bare" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}
