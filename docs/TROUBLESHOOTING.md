# Troubleshooting Guide

This guide helps you resolve common issues when using PolicyGuard.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Scanning Issues](#scanning-issues)
- [Policy Issues](#policy-issues)
- [Performance Issues](#performance-issues)
- [Output and Reporting Issues](#output-and-reporting-issues)
- [CI/CD Integration Issues](#cicd-integration-issues)
- [Common Error Messages](#common-error-messages)
- [Getting Help](#getting-help)

## Installation Issues

### Go Version Errors

**Problem**: `go: version "1.21" required`

**Solution**:
```bash
# Check your Go version
go version

# If version is older than 1.21, update Go:
# macOS (using Homebrew)
brew update && brew upgrade go

# Linux
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz

# Windows
# Download installer from https://go.dev/dl/
```

### Build Errors

**Problem**: `cannot find package "github.com/..."`

**Solution**:
```bash
# Update dependencies
go mod download
go mod tidy

# Clear module cache if needed
go clean -modcache
```

**Problem**: `command not found: policyguard`

**Solution**:
```bash
# Ensure $GOPATH/bin is in your PATH
export PATH=$PATH:$GOPATH/bin

# Or install to a system directory
sudo cp policyguard /usr/local/bin/
```

## Scanning Issues

### No Resources Found

**Problem**: "No resources found in scan"

**Common Causes**:
1. Wrong file path
2. File has syntax errors
3. File is not a valid Terraform file

**Solutions**:
```bash
# Verify file exists
ls -la main.tf

# Check file syntax with Terraform
terraform validate

# Try scanning with verbose mode
policyguard scan main.tf -v
```

### Parser Errors

**Problem**: "Failed to parse Terraform file"

**Solutions**:
1. **Check HCL syntax**:
   ```bash
   terraform fmt -check main.tf
   ```

2. **Look for common syntax issues**:
   - Missing closing braces `}`
   - Invalid attribute names
   - Incorrect string quotes

3. **Simplify the file** to identify the problematic section

### Unsupported Terraform Features

**Problem**: "Unsupported Terraform feature: X"

**Current Limitations**:
- Dynamic blocks are partially supported
- Module calls are not yet resolved
- Complex expressions may not be fully evaluated

**Workaround**:
Create separate files for complex configurations or use simplified versions for scanning.

## Policy Issues

### No Policies Found

**Problem**: "No policy files found in policies/"

**Solutions**:
```bash
# Check policy path exists
ls -la policies/

# Use custom policy path
policyguard scan main.tf --policy ./my-policies

# Create policies directory
mkdir -p policies
```

### Policy Validation Errors

**Problem**: "Policy validation failed"

**Common Issues**:

1. **Syntax Errors**:
   ```bash
   # Validate specific policy
   policyguard validate policies/my_policy.rego
   
   # Format policy file
   opa fmt policies/my_policy.rego
   ```

2. **Missing Imports**:
   ```rego
   # Add required imports at the top
   import future.keywords.contains
   import future.keywords.if
   ```

3. **Package Name Issues**:
   ```rego
   # Ensure package name is correct
   package policyguard
   ```

### Policies Not Detecting Violations

**Problem**: Policies don't catch expected violations

**Debugging Steps**:

1. **Test with minimal input**:
   ```bash
   # Create test file
   cat > test.tf << EOF
   resource "aws_s3_bucket" "test" {
     bucket = "test"
     acl    = "public-read-write"
   }
   EOF
   
   # Scan with specific policy
   policyguard scan test.tf --policy policies/aws/s3_bucket_public_access.rego
   ```

2. **Check policy logic**:
   ```rego
   # Add debug prints
   deny[violation] {
       resource := input.resource
       print("Resource type:", resource.type)
       print("Resource attributes:", resource.attributes)
       # ... rest of policy
   }
   ```

3. **Verify resource parsing**:
   ```bash
   # Use JSON output to see parsed resources
   policyguard scan test.tf --format json | jq '.resources'
   ```

## Performance Issues

### Slow Scanning

**Problem**: Scanning takes too long

**Solutions**:

1. **Scan specific files** instead of directories:
   ```bash
   # Instead of
   policyguard scan .
   
   # Use
   policyguard scan *.tf
   ```

2. **Reduce policy count**:
   ```bash
   # Use only required policies
   policyguard scan main.tf --policy policies/aws/s3_*.rego
   ```

3. **Check for large files**:
   ```bash
   # Find large Terraform files
   find . -name "*.tf" -size +1M
   ```

### Memory Usage

**Problem**: High memory consumption

**Solutions**:
- Break large Terraform configurations into smaller files
- Scan directories in batches
- Increase system memory or use a machine with more RAM

## Output and Reporting Issues

### No Output

**Problem**: Command completes but shows no output

**Solutions**:
```bash
# Check exit code
policyguard scan main.tf
echo $?

# Use verbose mode
policyguard scan main.tf -v

# Check if resources were found
policyguard scan main.tf --format json | jq '.summary'
```

### Formatting Issues

**Problem**: Output is not formatted correctly

**Solutions**:

1. **Terminal color issues**:
   ```bash
   # Disable colors if terminal doesn't support them
   NO_COLOR=1 policyguard scan main.tf
   ```

2. **JSON parsing errors**:
   ```bash
   # Validate JSON output
   policyguard scan main.tf --format json | jq .
   ```

### Output File Issues

**Problem**: Cannot write output file

**Solutions**:
```bash
# Check permissions
ls -la $(dirname output.json)

# Create directory if needed
mkdir -p reports
policyguard scan main.tf --output reports/scan.json
```

## CI/CD Integration Issues

### Exit Codes

**Problem**: CI/CD pipeline doesn't fail on violations

**Solution**:
```bash
# Use --fail-on-error flag
policyguard scan . --fail-on-error

# Check exit codes:
# 0 = Success, no violations
# 1 = Violations found
# 2 = Error during execution
```

### Path Issues in CI

**Problem**: "File not found" in CI environment

**Solutions**:
```yaml
# GitHub Actions - use correct working directory
- name: Scan Terraform
  run: |
    pwd
    ls -la
    policyguard scan terraform/ --fail-on-error
```

### Docker/Container Issues

**Problem**: "policyguard: not found" in container

**Solution**:
```dockerfile
# Add to Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o policyguard ./cmd/policyguard

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/policyguard /usr/local/bin/
```

## Common Error Messages

### "failed to load policies: no policy files found"

**Cause**: PolicyGuard cannot find any `.rego` files in the specified directory

**Fix**:
```bash
# Specify correct policy path
policyguard scan main.tf --policy /path/to/policies

# Or set environment variable
export POLICYGUARD_POLICY_PATH=/path/to/policies
```

### "failed to parse file: unexpected token"

**Cause**: Terraform file has syntax errors

**Fix**:
```bash
# Validate with Terraform first
terraform init
terraform validate

# Format the file
terraform fmt main.tf
```

### "policy compilation failed"

**Cause**: Rego policy has syntax errors

**Fix**:
```bash
# Test policy with OPA directly
opa eval -d policies/my_policy.rego "data.policyguard.deny"

# Format policy
opa fmt policies/my_policy.rego
```

### "resource type not supported"

**Cause**: PolicyGuard doesn't recognize the resource type

**Fix**:
- Check for typos in resource type
- Ensure you're using standard Terraform resource naming
- File an issue for new resource type support

## Getting Help

### Debug Mode

Enable debug logging for more information:
```bash
# Set log level
export POLICYGUARD_LOG_LEVEL=debug
policyguard scan main.tf -v

# Or use debug flag
policyguard scan main.tf --debug
```

### Logs and Diagnostics

Collect diagnostic information:
```bash
# System information
echo "OS: $(uname -a)"
echo "Go version: $(go version)"
echo "PolicyGuard version: $(policyguard version)"

# Test with minimal example
cat > minimal.tf << EOF
resource "aws_s3_bucket" "test" {
  bucket = "test"
}
EOF

policyguard scan minimal.tf -v
```

### Community Support

1. **GitHub Issues**: Report bugs or request features
   - Include PolicyGuard version
   - Provide minimal reproducible example
   - Include error messages and logs

2. **Documentation**: Check the latest docs
   - [README](../README.md)
   - [Policy Guide](POLICY_GUIDE.md)
   - [API Documentation](API.md)

3. **Examples**: Review working examples
   - Check `examples/` directory
   - Look at test files in `tests/`

### Common Fixes Checklist

- [ ] Update to latest PolicyGuard version
- [ ] Verify Go version is 1.21+
- [ ] Check file paths are correct
- [ ] Validate Terraform syntax
- [ ] Ensure policies are in correct format
- [ ] Try with a minimal example
- [ ] Check permissions on files/directories
- [ ] Review error messages carefully
- [ ] Enable verbose/debug mode
- [ ] Check environment variables

If issues persist, please open a GitHub issue with:
- PolicyGuard version (`policyguard version`)
- Go version (`go version`)
- Operating system
- Complete error message
- Minimal example to reproduce