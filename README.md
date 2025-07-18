# PolicyGuard

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20Windows-blue?style=for-the-badge" alt="Platform">
</p>

PolicyGuard is a security policy engine for Infrastructure as Code (IaC) that helps identify security issues and compliance violations in Terraform and OpenTofu configurations. It uses Open Policy Agent (OPA) to evaluate resources against customizable security policies.

## Features

- **Terraform & OpenTofu Support**: Parse both Terraform (.tf, .tf.json) and OpenTofu (.tofu, .tofu.json) configuration files
- **Policy Evaluation**: Evaluate resources against security policies using OPA
- **Multiple Output Formats**: Human-readable, JSON, JUnit, and SARIF formats
- **Customizable Policies**: Write your own policies in Rego
- **CI/CD Integration**: Exit codes and formats suitable for automation
- **Real-time Feedback**: Get immediate feedback on security violations
- **Remediation Suggestions**: Actionable fixes for security issues

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Commands](#commands)
- [Security Policies](#security-policies)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/ToluGIT/policyguard.git
cd policyguard

# Build the binary
go build -o policyguard ./cmd/policyguard

# Install to system path (optional)
sudo mv policyguard /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/ToluGIT/policyguard/cmd/policyguard@v0.2.0
```

### Prerequisites

- Go 1.21 or later
- Terraform or OpenTofu configuration files to scan

## Quick Start

1. **Scan a Terraform file**:
```bash
policyguard scan main.tf
```

2. **Scan an OpenTofu file**:
```bash
policyguard scan main.tofu
```

3. **Scan a directory (supports both .tf and .tofu files)**:
```bash
policyguard scan ./infrastructure
```

4. **Get JSON output**:
```bash
policyguard scan main.tf --format json
```

5. **Fail on violations (for CI/CD)**:
```bash
policyguard scan main.tf --fail-on-error
```

## Usage

### Basic Scanning

```bash
# Scan Terraform files
policyguard scan vpc.tf

# Scan OpenTofu files
policyguard scan vpc.tofu

# Scan multiple files (both .tf and .tofu)
policyguard scan *.tf *.tofu

# Scan a directory recursively (finds all .tf, .tf.json, .tofu, .tofu.json files)
policyguard scan ./infrastructure

# Use custom policies
policyguard scan main.tf --policy ./custom-policies

# Output to file
policyguard scan main.tf --output report.txt
```

### Output Formats

PolicyGuard supports multiple output formats:

- **human** (default): Human-readable format with colors
- **json**: Machine-readable JSON format
- **junit**: JUnit XML format for CI systems
- **sarif**: SARIF format for GitHub/GitLab integration

```bash
# JSON output
policyguard scan main.tf --format json

# JUnit for CI
policyguard scan main.tf --format junit --output results.xml

# SARIF for GitHub
policyguard scan main.tf --format sarif --output results.sarif
```

## Commands

### `scan` - Analyze Terraform Files

```bash
policyguard scan [path] [flags]
```

**Flags:**
- `--policy, -p`: Path to policy files (default: `policies/`)
- `--format, -f`: Output format (human, json, junit, sarif)
- `--output, -o`: Output file (default: stdout)
- `--fail-on-error`: Exit with non-zero code on violations

**Examples:**
```bash
# Scan with custom policies
policyguard scan main.tf --policy ./security-policies

# Generate JSON report
policyguard scan ./infra --format json --output report.json

# CI/CD mode
policyguard scan . --fail-on-error
```

### `validate` - Validate Policy Files

```bash
policyguard validate [path] [flags]
```

**Flags:**
- `--verbose, -v`: Show detailed validation output

**Examples:**
```bash
# Validate all policies
policyguard validate policies/

# Validate specific policy
policyguard validate policies/aws/s3_encryption.rego
```

### `policy` - Manage Policies

#### List Policies
```bash
policyguard policy list [flags]
```

**Flags:**
- `--policy, -p`: Path to policy files
- `--format, -f`: Output format (human, json)

**Examples:**
```bash
# List all policies
policyguard policy list

# List in JSON format
policyguard policy list --format json
```

#### Show Policy Details
```bash
policyguard policy show [policy-id] [flags]
```

**Flags:**
- `--policy, -p`: Path to policy files
- `--format, -f`: Output format (human, json, raw)

**Examples:**
```bash
# Show policy details
policyguard policy show s3_bucket_encryption

# Show raw policy content
policyguard policy show ec2_instance_security --format raw
```

## Security Policies

PolicyGuard includes built-in security policies for AWS resources:

### AWS S3 Policies
- **s3_bucket_encryption**: Ensure S3 buckets have encryption enabled
- **s3_bucket_public_access**: Prevent public access to S3 buckets
- **s3_bucket_logging**: Ensure S3 access logging is enabled

### AWS EC2 Policies
- **ec2_instance_security**: Comprehensive EC2 security checks
  - No public IP addresses
  - Encrypted EBS volumes
  - IMDSv2 enforcement
  - Secure security groups

### AWS Security Group Policies
- Prevent unrestricted inbound access
- No SSH open to the world
- No unrestricted outbound access

### Custom Policies

You can write custom policies in Rego. Create a `.rego` file in your policies directory:

```rego
package policyguard

import future.keywords.contains
import future.keywords.if

# Ensure RDS instances have encryption enabled
deny[violation] {
    resource := input.resource
    resource.type == "aws_db_instance"
    not resource.attributes.storage_encrypted
    
    violation := {
        "id": sprintf("rds-no-encryption-%s", [resource.name]),
        "policy_id": "rds_encryption",
        "severity": "high",
        "message": sprintf("RDS instance '%s' does not have encryption enabled", [resource.name]),
        "details": "RDS instances should have encryption enabled for data at rest",
        "remediation": "Set storage_encrypted = true"
    }
}
```

## Configuration

PolicyGuard can be configured using:

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration file** (`.policyguard.yaml`)

### Configuration File Example

```yaml
# .policyguard.yaml
policy_path: ./policies
output_format: human
fail_on_error: false
verbose: false
```

### Environment Variables

```bash
export POLICYGUARD_POLICY_PATH=./custom-policies
export POLICYGUARD_OUTPUT_FORMAT=json
export POLICYGUARD_FAIL_ON_ERROR=true
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install PolicyGuard
        run: go install github.com/ToluGIT/policyguard/cmd/policyguard@v0.2.0
      
      - name: Run Security Scan
        run: policyguard scan . --fail-on-error --format sarif --output results.sarif
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - go install github.com/ToluGIT/policyguard/cmd/policyguard@v0.2.0
    - policyguard scan . --fail-on-error --format junit --output report.xml
  artifacts:
    reports:
      junit: report.xml
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: policyguard
        name: PolicyGuard Security Scan
        entry: policyguard scan
        language: system
        files: '\.tf$'
        pass_filenames: true
```

## Development

### Project Structure

```
policyguard/
├── cmd/
│   └── policyguard/    # CLI application
├── pkg/
│   ├── analyzer/       # Core analysis logic
│   ├── parser/         # IaC file parsers
│   │   └── terraform/  # Terraform HCL parser
│   ├── policy/         # Policy engine (OPA integration)
│   ├── remediation/    # Remediation suggestions
│   ├── reporter/       # Report generation
│   └── types/          # Common types
├── policies/           # Default security policies
│   └── aws/           # AWS-specific policies
├── examples/          # Example configurations
└── tests/             # Test files
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ToluGIT/policyguard.git
cd policyguard

# Install dependencies
go mod download

# Run tests
make test

# Run integration tests
make integration-test

# Build binary
make build

# Install locally
make install
```

### Running Tests

```bash
# Unit tests
make test

# Integration tests
make integration-test

# All tests
make test-all

# Test coverage
make coverage
```

### Adding New Policies

1. Create a new `.rego` file in `policies/[provider]/`
2. Follow the policy structure:
   ```rego
   package policyguard
   
   deny[violation] {
       # Policy logic here
       violation := {
           "id": "unique-id",
           "policy_id": "policy_name",
           "severity": "high|medium|low",
           "message": "Description",
           "details": "Detailed explanation",
           "remediation": "How to fix"
       }
   }
   ```
3. Add tests for your policy
4. Run `policyguard validate` to ensure syntax is correct

## Contributing

Contributions are supported! Please see [Contributing Guide](CONTRIBUTING.md) for details.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Open Policy Agent](https://www.openpolicyagent.org/) for the policy engine
- [HashiCorp HCL](https://github.com/hashicorp/hcl) for Terraform parsing
- [Cobra](https://github.com/spf13/cobra) for CLI framework

## Additional Resources

- [Policy Writing Guide](docs/POLICY_GUIDE.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
- [API Documentation](docs/API.md)
- [Security Best Practices](docs/SECURITY.md)


