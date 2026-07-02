# Security Best Practices

This guide provides security best practices for using PolicyGuard and writing secure Infrastructure as Code.

## Table of Contents

- [PolicyGuard Security](#policyguard-security)
- [Infrastructure Security Principles](#infrastructure-security-principles)
- [AWS Security Best Practices](#aws-security-best-practices)
- [Policy Security Guidelines](#policy-security-guidelines)
- [CI/CD Security](#cicd-security)
- [Compliance and Standards](#compliance-and-standards)

## PolicyGuard Security

### Installation Security

1. **Verify Downloads**:
   ```bash
   # Verify checksums when available
   sha256sum policyguard
   
   # Use official sources
   go install github.com/ToluGIT/policyguard/cmd/policyguard@latest
   ```

2. **Secure Storage**:
   - Store PolicyGuard binary in protected directories
   - Limit execution permissions to authorized users
   - Keep the binary updated to latest version

### Runtime Security

1. **Policy Source Control**:
   ```bash
   # Keep policies in version control
   git add policies/
   git commit -m "Add security policies"
   
   # Review policy changes
   git diff policies/
   ```

2. **Secure Policy Loading**:
   - Only load policies from trusted sources
   - Review custom policies before use
   - Use read-only policy directories in production

3. **Output Handling**:
   ```bash
   # Be careful with sensitive information in reports
   policyguard scan main.tf --output report.json
   chmod 600 report.json
   ```

### Securing PolicyGuard Itself (engine threat model)

PolicyGuard parses untrusted Infrastructure-as-Code and **loads and executes Rego policies** from the directory given by `--policy`. A policy is therefore executable code, and the input it runs against may contain sensitive values (for example, a credential hardcoded in a `.tf` file). The engine treats its own attack surface as a first-class concern.

| Threat | Control | Status |
|--------|---------|--------|
| A malicious policy exfiltrates the parsed infrastructure (which may contain hardcoded credentials) by calling a network built-in such as `http.send` or `net.lookup_ip_addr`. | The OPA engine is compiled and evaluated with a restricted capability set that **removes every non-deterministic built-in** (`http.send`, `net.lookup_ip_addr`, `opa.runtime`, `io.jwt.encode_sign`, `io.jwt.encode_sign_raw`, `io.jwt.decode_verify`, `rand.intn`, `time.now_ns`, `uuid.rfc4122`) and disallows all outbound network access (`AllowNet` is empty). A policy that references one of these fails to compile, so the restriction is enforced **at load time, before any evaluation runs**. | Implemented (`pkg/policy/opa/engine.go`, `restrictedCapabilities`). |
| A scan that errors (failed policy load, unparseable file) silently passes a CI gate, or a real violation is mistaken for a crash. | Distinct exit codes: **0** clean, **1** violations found under `--fail-on-error`, **2** the scan failed to run (bad input, unreadable/invalid policy, internal error). A broken scan fails the build with a code distinguishable from "violations found". | Implemented (`cmd/policyguard/main.go`; guarded by `TestCLIExitCodes`). |
| A report or log re-exposes a credential found in the scanned IaC. | Treat report files as sensitive (`chmod 600`); JSON output is full-fidelity by design. Do not echo report contents into world-readable CI logs on public repositories. | Operational guidance; masking of credential-like values is on the roadmap. |

**Design principle:** a security policy is a *pure function of its input*. Nothing a legitimate misconfiguration check needs is non-deterministic, so removing those built-ins costs the policy author nothing while closing the exfiltration path. If you maintain custom policies, keep them pure — a policy that needs the network is doing something a policy should not.

**Defense in depth still applies:** the capability sandbox does not remove the value of reviewing custom policies before use (above). Load policies from trusted, version-controlled sources and review changes.

### Hosting the GUI

`policyguard serve` starts a web server that accepts **untrusted uploaded/pasted Terraform** and scans it in-process. Its attack surface is treated as first-class.

| Threat | Control |
|--------|---------|
| A remote caller runs untrusted Rego by pointing the engine at an attacker-controlled policy directory. | The server **only** ever loads the trusted, embedded policy set (`LoadEmbeddedPolicies`). There is no request parameter that selects a `--policy` path. The OPA capability sandbox (above) still applies on top. |
| Path traversal — an upload filename or a finding's recorded path reads/writes outside the scan sandbox. | Upload filenames are reduced to a sanitized base name (no separators, allowlisted characters); uploads land only in a per-request `os.MkdirTemp` dir. Evidence is read by joining that temp dir with each finding's path **after** it has been rebased to a guaranteed-relative, no-`..` name — a path that resolves outside the temp dir falls back to its base name and cannot escape. |
| Resource exhaustion / DoS. | Request body capped with `http.MaxBytesReader`; per-request size, file-count, and scan-timeout (`context`) limits, tightened in `--public` mode (1 MiB / 25 files / 15 s vs 16 MiB / 200 files / 60 s); a per-client fixed-window rate limit whose table is pruned so it can't grow without bound; multipart spill files are cleaned up after each request. |
| Cross-site scripting from crafted IaC. | The dashboard fragment is rendered by `html/template` (context-aware auto-escaping), so a resource name or value containing `<img onerror=…>` / `</script>` is inert text. Guarded by `TestScanEscapesMaliciousContent`. A strict Content-Security-Policy (`script-src 'self'`, `default-src 'none'`) plus `X-Frame-Options: DENY` and `nosniff` are sent on every response. |
| Exposure on an untrusted network. | The server **binds to `127.0.0.1` by default** — it is not reachable off-host unless you opt in. `--public` is the explicit, hardened mode for container hosting (upload/paste only — no filesystem path scanning — with the tighter limits above). Uploaded content is written to a temp dir and **deleted after each scan**. |

Run the GUI behind your own TLS-terminating reverse proxy if you expose it beyond localhost. As with any scanner, treat the IaC you upload as sensitive — it is processed on the host running `serve`.

### Supply-chain integrity

A scanner you run in CI with access to your infrastructure code is itself part of
your supply chain. PolicyGuard's releases are built and signed so you can verify
*what* you are running and *where* it came from before you trust it.

| Concern | Control |
|---------|---------|
| A tampered binary is substituted for a release. | Every release publishes a `checksums.txt` (SHA-256 of each binary). Verify with `sha256sum --check --ignore-missing checksums.txt`. |
| The checksums file itself is forged. | `checksums.txt` is signed with **cosign keyless signing**; the signature (`.sig`) and certificate (`.pem`) are bound to the release workflow's GitHub OIDC identity — there is no long-lived private key to steal. Verify with `cosign verify-blob` against `--certificate-identity-regexp 'https://github.com/ToluGIT/policyguard/\.github/workflows/release\.yml@refs/tags/.+'` (pinned to the release workflow on a tag, so a signature from any other workflow does not verify) and `--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'` (full command in the README). |
| A tampered container image is pulled. | The GHCR image is signed by **immutable digest** (not tag) with the same keyless identity, and is built with provenance + SBOM attestations. Verify with `cosign verify`. |
| You cannot tell what went into a build. | Each release attaches an **SPDX SBOM** (`policyguard.sbom.spdx.json`) listing the Go module graph compiled into the binaries. |
| Policy integrity. | The default policy set is **embedded in the binary** (`//go:embed all:policies`), so verifying the binary's checksum/signature also verifies the policies it ships with — they are not loaded from a separately-mutable location at runtime unless you pass `--policy`. |

The signing and SBOM steps run in the release workflow
(`.github/workflows/release.yml`) only on tag builds, using GitHub Actions OIDC
(`id-token: write`) — no signing secret is stored in the repository.

**Note on the container vs. the release binaries.** The container image is built
*separately* from the downloadable release binaries (both from the same source
commit) so the image can be multi-arch (amd64/arm64). Go builds are not
guaranteed bit-for-bit identical across jobs, so do not expect the in-container
binary to match a release binary's checksum. Verify the image with its own
signature (`cosign verify ghcr.io/...`), and verify a downloaded binary against
the signed `checksums.txt` — each is signed against the build that produced it.

## Infrastructure Security Principles

### 1. Principle of Least Privilege

**Always grant minimum required permissions:**

```hcl
# Bad: Overly permissive
resource "aws_iam_role_policy" "bad" {
  role = aws_iam_role.example.id
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Good: Specific permissions
resource "aws_iam_role_policy" "good" {
  role = aws_iam_role.example.id
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        aws_s3_bucket.example.arn,
        "${aws_s3_bucket.example.arn}/*"
      ]
    }]
  })
}
```

### 2. Defense in Depth

**Layer security controls:**

```hcl
# Multiple layers of security for RDS
resource "aws_db_instance" "secure" {
  # Layer 1: Encryption at rest
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds.arn
  
  # Layer 2: Encryption in transit
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  # Layer 3: Network isolation
  db_subnet_group_name   = aws_db_subnet_group.private.name
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.rds.id]
  
  # Layer 4: Access control
  iam_database_authentication_enabled = true
  
  # Layer 5: Backup and recovery
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  
  # Layer 6: Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql"]
  performance_insights_enabled    = true
}
```

### 3. Secure by Default

**Start with secure configurations:**

```hcl
# S3 bucket with secure defaults
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_acl" "secure" {
  bucket = aws_s3_bucket.secure.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "secure" {
  bucket = aws_s3_bucket.secure.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure" {
  bucket = aws_s3_bucket.secure.id
  
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-logs/"
}
```

## AWS Security Best Practices

### S3 Security

1. **Access Control**:
   ```hcl
   # Use bucket policies for fine-grained access
   resource "aws_s3_bucket_policy" "secure" {
     bucket = aws_s3_bucket.example.id
     
     policy = jsonencode({
       Statement = [{
         Sid    = "DenyInsecureTransport"
         Effect = "Deny"
         Principal = "*"
         Action = "s3:*"
         Resource = [
           aws_s3_bucket.example.arn,
           "${aws_s3_bucket.example.arn}/*"
         ]
         Condition = {
           Bool = {
             "aws:SecureTransport" = "false"
           }
         }
       }]
     })
   }
   ```

2. **Data Protection**:
   ```hcl
   # Enable MFA delete for critical buckets
   resource "aws_s3_bucket_versioning" "critical" {
     bucket = aws_s3_bucket.critical.id
     
     versioning_configuration {
       status     = "Enabled"
       mfa_delete = "Enabled"
     }
   }
   ```

### EC2 Security

1. **Instance Security**:
   ```hcl
   resource "aws_instance" "secure" {
     # Use latest AMI
     ami = data.aws_ami.latest_amazon_linux.id
     
     # Enable detailed monitoring
     monitoring = true
     
     # Use IAM instance profile
     iam_instance_profile = aws_iam_instance_profile.ec2.name
     
     # Disable public IP
     associate_public_ip_address = false
     
     # Enable termination protection for production
     disable_api_termination = var.environment == "production"
     
     # Enforce IMDSv2
     metadata_options {
       http_endpoint               = "enabled"
       http_tokens                 = "required"
       http_put_response_hop_limit = 1
     }
     
     # Encrypted root volume
     root_block_device {
       encrypted   = true
       kms_key_id  = aws_kms_key.ebs.arn
       volume_type = "gp3"
     }
     
     # User data security
     user_data = base64encode(templatefile("userdata.sh", {
       secrets = data.aws_secretsmanager_secret_version.app.secret_string
     }))
   }
   ```

2. **Security Groups**:
   ```hcl
   # Restrictive security group
   resource "aws_security_group" "app" {
     name_prefix = "app-"
     description = "Security group for application"
     vpc_id      = aws_vpc.main.id
     
     # No ingress rules by default
     # Add specific rules as needed
     
     egress {
       description = "Allow HTTPS outbound"
       from_port   = 443
       to_port     = 443
       protocol    = "tcp"
       cidr_blocks = ["0.0.0.0/0"]
     }
     
     lifecycle {
       create_before_destroy = true
     }
   }
   
   # Separate rule resources for better management
   resource "aws_security_group_rule" "app_from_alb" {
     type                     = "ingress"
     from_port                = 8080
     to_port                  = 8080
     protocol                 = "tcp"
     source_security_group_id = aws_security_group.alb.id
     security_group_id        = aws_security_group.app.id
     description              = "Allow traffic from ALB"
   }
   ```

### RDS Security

```hcl
resource "aws_db_instance" "secure" {
  # Encryption
  storage_encrypted               = true
  kms_key_id                     = aws_kms_key.rds.arn
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
  
  # Network security
  db_subnet_group_name = aws_db_subnet_group.private.name
  publicly_accessible  = false
  
  # Authentication
  iam_database_authentication_enabled = true
  
  # Backup
  backup_retention_period         = 30
  backup_window                  = "03:00-04:00"
  maintenance_window             = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot          = true
  deletion_protection            = true
  skip_final_snapshot            = false
  final_snapshot_identifier      = "${var.db_name}-final-${formatdate("YYYY-MM-DD-hhmmss", timestamp())}"
  
  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  # Parameter group for security settings
  parameter_group_name = aws_db_parameter_group.secure.name
}

resource "aws_db_parameter_group" "secure" {
  family = "postgres13"
  
  parameter {
    name  = "log_statement"
    value = "all"
  }
  
  parameter {
    name  = "log_connections"
    value = "1"
  }
  
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
}
```

### IAM Security

```hcl
# Enforce MFA for sensitive operations
data "aws_iam_policy_document" "require_mfa" {
  statement {
    sid    = "DenyAllExceptListedIfNoMFA"
    effect = "Deny"
    
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken"
    ]
    
    resources = ["*"]
    
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

# Time-based access control
resource "aws_iam_role" "temporary_access" {
  name = "temporary-admin-access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        DateGreaterThan = {
          "aws:CurrentTime" = "2024-01-01T00:00:00Z"
        }
        DateLessThan = {
          "aws:CurrentTime" = "2024-01-02T00:00:00Z"
        }
        IpAddress = {
          "aws:SourceIp" = ["10.0.0.0/8"]
        }
      }
    }]
  })
}
```

## Policy Security Guidelines

### 1. Policy Validation

```rego
# Include metadata in policies
package policyguard

# metadata
# title: S3 Bucket Encryption Policy
# description: Ensures all S3 buckets have encryption enabled
# authors:
#   - security-team@example.com
# organizations:
#   - example-corp
# severity: high
# tags:
#   - aws
#   - s3
#   - encryption
#   - compliance

deny[violation] {
    # Policy logic here
}
```

### 2. Policy Testing

```rego
# Comprehensive test coverage
package policyguard_test

test_s3_encryption_with_aes256 {
    # Test passes with AES256
    not deny[_] with input as {
        "resource": {
            "type": "aws_s3_bucket",
            "attributes": {
                "server_side_encryption_configuration": {
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "AES256"
                        }
                    }
                }
            }
        }
    }
}

test_s3_encryption_with_kms {
    # Test passes with KMS
    not deny[_] with input as {
        "resource": {
            "type": "aws_s3_bucket",
            "attributes": {
                "server_side_encryption_configuration": {
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "aws:kms",
                            "kms_master_key_id": "arn:aws:kms:..."
                        }
                    }
                }
            }
        }
    }
}

test_s3_no_encryption_fails {
    # Test fails without encryption
    deny[_] with input as {
        "resource": {
            "type": "aws_s3_bucket",
            "attributes": {}
        }
    }
}
```

### 3. Secure Policy Distribution

```bash
# Sign policies for integrity
gpg --sign policies.tar.gz

# Verify before use
gpg --verify policies.tar.gz.sig policies.tar.gz

# Use secure channels for distribution
git clone git@github.com:company/security-policies.git --branch verified
```

## CI/CD Security

### 1. Secure Pipeline Configuration

```yaml
# GitHub Actions with security scanning
name: Secure Terraform Pipeline
on:
  pull_request:
    paths:
      - '**.tf'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
          
      - name: Setup PolicyGuard
        run: |
          # Verify checksum
          curl -L -o policyguard https://releases.policyguard.io/latest/policyguard-linux-amd64
          curl -L -o checksums.txt https://releases.policyguard.io/latest/checksums.txt
          grep policyguard-linux-amd64 checksums.txt | sha256sum -c
          chmod +x policyguard
          
      - name: Run Security Scan
        run: |
          ./policyguard scan . \
            --policy verified-policies/ \
            --format sarif \
            --output results.sarif
            
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          
      - name: Fail on Critical
        run: |
          CRITICAL=$(jq '.runs[0].results[] | select(.level == "error") | length' results.sarif)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical security violations found!"
            exit 1
          fi
```

### 2. Secret Management

```hcl
# Never hardcode secrets
# Bad
resource "aws_db_instance" "bad" {
  master_username = "admin"
  master_password = "SuperSecret123!"  # NEVER DO THIS
}

# Good - Use AWS Secrets Manager
resource "random_password" "db" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db" {
  name_prefix = "rds-password-"
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = random_password.db.result
}

resource "aws_db_instance" "good" {
  master_username = "admin"
  master_password = aws_secretsmanager_secret_version.db.secret_string
}
```

### 3. Audit Trail

```hcl
# Enable CloudTrail for audit
resource "aws_cloudtrail" "audit" {
  name                          = "security-audit-trail"
  s3_bucket_name               = aws_s3_bucket.audit.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/*"]
    }
  }
  
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
}
```

## Compliance and Standards

### 1. CIS Benchmarks

Implement CIS AWS Foundations Benchmark controls:

```rego
# CIS 2.1.1 - Ensure S3 bucket encryption
deny[violation] {
    resource := input.resource
    resource.type == "aws_s3_bucket"
    not resource.attributes.server_side_encryption_configuration
    
    violation := {
        "id": sprintf("cis-2.1.1-%s", [resource.name]),
        "policy_id": "cis_2_1_1_s3_encryption",
        "severity": "high",
        "message": "CIS 2.1.1: S3 bucket should have encryption enabled",
        "details": "CIS AWS Foundations Benchmark requires all S3 buckets to be encrypted",
        "remediation": "Enable server-side encryption with AES256 or KMS"
    }
}
```

### 2. HIPAA Compliance

For healthcare applications:

```hcl
# HIPAA-compliant RDS configuration
resource "aws_db_instance" "hipaa" {
  # Encryption requirements
  storage_encrypted = true
  kms_key_id       = aws_kms_key.hipaa.arn
  
  # Audit requirements
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
  
  # Backup requirements
  backup_retention_period = 35  # HIPAA requires 6 years for some data
  
  # Access control
  iam_database_authentication_enabled = true
  
  # Network isolation
  publicly_accessible = false
  
  tags = {
    Compliance = "HIPAA"
    DataClass  = "PHI"
  }
}
```

### 3. PCI-DSS Compliance

For payment card data:

```hcl
# PCI-DSS compliant network segmentation
resource "aws_vpc" "pci" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name       = "PCI-DSS-VPC"
    Compliance = "PCI-DSS"
  }
}

# Separate subnets for PCI data
resource "aws_subnet" "pci_private" {
  vpc_id            = aws_vpc.pci.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  
  tags = {
    Name       = "PCI-Private-Subnet"
    Compliance = "PCI-DSS"
    Scope      = "CDE"  # Cardholder Data Environment
  }
}

# Flow logs for PCI compliance
resource "aws_flow_log" "pci" {
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.pci_logs.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.pci.id
  
  tags = {
    Compliance = "PCI-DSS-Requirement-10"
  }
}
```

## Security Checklist

Before deploying infrastructure:

- [ ] All resources are tagged appropriately
- [ ] Encryption is enabled for data at rest
- [ ] Encryption is enabled for data in transit
- [ ] Least privilege IAM policies are applied
- [ ] Network access is restricted appropriately
- [ ] Logging and monitoring are configured
- [ ] Backup and disaster recovery are configured
- [ ] Secret management is implemented
- [ ] Security groups follow least privilege
- [ ] Public access is disabled where not required
- [ ] MFA is enforced for sensitive operations
- [ ] Compliance requirements are met
- [ ] Security scanning is integrated in CI/CD
- [ ] Incident response procedures are documented

## Resources

- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)