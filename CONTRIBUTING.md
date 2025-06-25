# Contributing to PolicyGuard

Thank you for your interest in contributing to PolicyGuard! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Process](#development-process)
- [Style Guidelines](#style-guidelines)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Go 1.21 or later
- Make (optional but recommended)
- Git

### Setting Up Your Development Environment

1. **Fork the repository**
   ```bash
   # Click "Fork" on GitHub
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/policyguard.git
   cd policyguard
   ```

3. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/ToluGIT/policyguard.git
   ```

4. **Install dependencies**
   ```bash
   go mod download
   ```

5. **Build the project**
   ```bash
   make build
   ```

6. **Run tests**
   ```bash
   make test
   ```

## How to Contribute

### Types of Contributions

- **Bug Fixes**: Fix issues reported in GitHub Issues
- **Features**: Add new functionality
- **Documentation**: Improve or add documentation
- **Tests**: Add missing tests or improve existing ones
- **Policies**: Add new security policies
- **Performance**: Optimize code for better performance

### Finding Issues to Work On

- Check issues labeled `good first issue`
- Look for issues labeled `help wanted`
- Check the roadmap in the README

## Development Process

### 1. Create a Branch

```bash
# Update your local repository
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feature/your-feature-name
# Or for bugs
git checkout -b fix/issue-description
```

### 2. Make Your Changes

Follow these guidelines:
- Write clean, readable code
- Add comments for complex logic
- Follow existing code style
- Update documentation as needed
- Add tests for new functionality

### 3. Test Your Changes

```bash
# Run all tests
make test-all

# Run specific tests
go test ./pkg/parser/...

# Run integration tests
make integration-test

# Check code coverage
make coverage
```

### 4. Commit Your Changes

```bash
# Stage your changes
git add .

# Commit with a descriptive message
git commit -m "feat: add support for CloudFormation parsing

- Add CloudFormation parser implementation
- Add tests for parser
- Update documentation"
```

#### Commit Message Format

Follow the conventional commits format:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

## Style Guidelines

### Go Code Style

1. **Follow Go conventions**
   ```go
   // Good: Exported function with comment
   // Parse parses a Terraform file and returns resources
   func Parse(ctx context.Context, path string) ([]Resource, error) {
       // Implementation
   }
   ```

2. **Error handling**
   ```go
   // Always check errors
   if err != nil {
       return fmt.Errorf("failed to parse %s: %w", path, err)
   }
   ```

3. **Use meaningful variable names**
   ```go
   // Bad
   r := Resource{}
   
   // Good
   resource := Resource{}
   ```

4. **Format your code**
   ```bash
   go fmt ./...
   # or
   make fmt
   ```

### Policy Style

1. **Follow Rego conventions**
   ```rego
   # Good: Clear rule with comments
   # Deny S3 buckets without encryption
   deny[violation] {
       resource := input.resource
       resource.type == "aws_s3_bucket"
       not resource.attributes.server_side_encryption_configuration
       
       violation := {
           "id": sprintf("s3-no-encryption-%s", [resource.name]),
           "policy_id": "s3_bucket_encryption",
           "severity": "high",
           "message": "S3 bucket does not have encryption enabled",
           "details": "Enable server-side encryption",
           "remediation": "Add server_side_encryption_configuration"
       }
   }
   ```

2. **Test your policies**
   ```rego
   test_s3_encryption_fails {
       deny[_] with input as {
           "resource": {
               "type": "aws_s3_bucket",
               "attributes": {}
           }
       }
   }
   ```

## Testing

### Unit Tests

```go
func TestParser_Parse(t *testing.T) {
    parser := New()
    
    tests := []struct {
        name    string
        input   string
        want    []Resource
        wantErr bool
    }{
        {
            name:  "valid terraform",
            input: `resource "aws_s3_bucket" "test" {}`,
            want:  []Resource{{Type: "aws_s3_bucket", Name: "test"}},
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := parser.Parse(context.Background(), tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Parse() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Integration Tests

```go
// +build integration

func TestCLI_Scan(t *testing.T) {
    // Test the full CLI workflow
}
```

### Policy Tests

```bash
# Test a specific policy
opa test policies/aws/s3_encryption.rego policies/aws/s3_encryption_test.rego

# Test all policies
opa test policies/
```

## Submitting Changes

### 1. Push Your Branch

```bash
git push origin feature/your-feature-name
```

### 2. Create a Pull Request

1. Go to your fork on GitHub
2. Click "New Pull Request"
3. Select your branch
4. Fill out the PR template:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] New policy

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] My code follows the project style guidelines
- [ ] I have added tests for my changes
- [ ] I have updated documentation as needed
- [ ] All tests pass locally
```

### 3. Code Review Process

- Maintainers will review your PR
- Address any feedback
- Once approved, your PR will be merged

## Reporting Issues

### Bug Reports

When reporting bugs, include:

1. **Environment details**
   - PolicyGuard version
   - Go version
   - Operating system

2. **Steps to reproduce**
   ```bash
   policyguard scan example.tf
   ```

3. **Expected behavior**
   What should happen

4. **Actual behavior**
   What actually happens

5. **Error messages**
   Include full error output

### Feature Requests

For feature requests, describe:
- The problem you're trying to solve
- Your proposed solution
- Alternative solutions considered
- Examples of how it would work

## Development Tips

### Running Locally

```bash
# Build and run
go run cmd/policyguard/main.go scan examples/terraform/insecure_s3.tf

# With debugging
POLICYGUARD_LOG_LEVEL=debug go run cmd/policyguard/main.go scan examples/terraform/insecure_s3.tf -v
```

### Debugging

```go
// Add debug logging
import "github.com/ToluGIT/policyguard/pkg/logger"

logger.Debug("Processing resource: %+v", resource)
```

### Performance Profiling

```bash
# CPU profiling
go test -cpuprofile cpu.prof -bench .
go tool pprof cpu.prof

# Memory profiling
go test -memprofile mem.prof -bench .
go tool pprof mem.prof
```

## Release Process

1. Update version in `version.go`
2. Update CHANGELOG.md
3. Create a release PR
4. After merge, tag the release
5. Build and publish binaries

## Questions?

- Open an issue for questions
- Join our community discussions
- Check existing documentation

Thank you for contributing to PolicyGuard! 🎉