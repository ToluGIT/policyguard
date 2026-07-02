# Demo fixture for the README scan demo (scripts/demo.sh).
# Deliberately insecure so the scan produces a stable, illustrative set of
# findings. All values are synthetic.

resource "aws_s3_bucket" "data" {
  bucket = "acme-customer-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
