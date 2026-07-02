# Benchmark fixture: EC2 instances and security groups with explicit
# misconfigurations. Security attributes are set to their insecure values
# explicitly (not omitted) so the expected findings are unambiguous.

resource "aws_instance" "exposed" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = true # -> ec2_instance_public_ip

  metadata_options {
    http_tokens = "optional" # IMDSv1 allowed -> ec2_instance_imdsv2
  }

  root_block_device {
    encrypted = false # -> ec2_instance_encryption
  }
}

resource "aws_security_group" "ssh_to_world" {
  name = "bench-ssh-open"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # -> security_group_ssh_open
  }
}

resource "aws_security_group" "all_open" {
  name = "bench-all-open"

  ingress {
    description = "All traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # -> security_group_ssh_open (protocol -1)
                                # and security_group_unrestricted (from/to 0)
  }
}
