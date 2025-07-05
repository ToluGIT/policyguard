# Testing PolicyGuard

This document provides comprehensive testing guidance for PolicyGuard, covering unit tests, integration tests, and manual testing procedures.

## Table of Contents

- [Quick Start](#quick-start)
- [Unit Testing](#unit-testing)
- [Integration Testing](#integration-testing)
- [Test Coverage](#test-coverage)
- [Manual Testing](#manual-testing)
- [Error Handling & Logging](#error-handling--logging)
- [Performance Testing](#performance-testing)
- [Adding New Tests](#adding-new-tests)

## Quick Start

```bash
# Run all tests (unit + integration)
make test-all

# Run only unit tests
go test ./...

# Run only integration tests
make integration-test

# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

## Unit Testing

Unit tests verify individual components in isolation.

### Running Unit Tests

```bash
# Run all unit tests
go test ./... -v

# Run tests with coverage
go test ./... -v -cover

# Run specific package tests
go test ./pkg/parser/terraform -v -cover
go test ./pkg/logger -v -cover
go test ./pkg/policy -v -cover
go test ./pkg/reporter/human -v -cover
```

### Current Unit Test Coverage

- **Parser (Terraform)**: 70.8% coverage
  - Parsing S3 buckets, EC2 instances, security groups
  - OpenTofu support (.tofu and .tofu.json files)
  - Error handling for invalid HCL
  - Directory parsing

- **Analyzer**: 90.5% coverage
  - File and directory analysis
  - Error handling scenarios
  - Component integration

- **Logger**: 50.7% coverage
  - Log level filtering
  - Formatted output
  - Component-specific loggers with prefixes
  - Log level parsing

- **Reporter (Human)**: 28.8% coverage
  - Pass rate calculation
  - Report generation
  - Resource violation counting

- **Reporter (JSON)**: 77.3% coverage
  - JSON output formatting
  - Pass rate calculation
  - Violation summarization

## Integration Testing

Integration tests verify the complete PolicyGuard pipeline from parsing to reporting.

### What Integration Tests Cover

1. **Full Pipeline Testing**
   - Parsing Terraform/OpenTofu configurations
   - Loading and evaluating OPA policies
   - Generating reports in multiple formats (Human, JSON, SARIF, JUnit)
   - Verifying correct violation detection

2. **CLI Command Testing**
   - `scan` command with various options
   - `validate` command for policy validation
   - `policy list` and `policy show` commands
   - Error handling and edge cases

3. **Component Integration**
   - Analyzer component integration
   - Parser, Policy Engine, and Reporter working together
   - Multi-file and directory analysis

4. **Performance Testing**
   - Large file analysis
   - Concurrent processing
   - Resource usage validation

### Running Integration Tests

```bash
# Run all integration tests
make integration-test

# Run specific integration test
go test -v -tags=integration -run TestFullPipeline ./tests/integration/

# Run with coverage
go test -v -tags=integration -cover ./tests/integration/

# Run integration tests with verbose output
go test -v -tags=integration ./tests/integration/
```

### Integration Test Structure

- **TestFullPipeline**: Complete analysis pipeline
- **TestCLIScanCommand**: CLI scan command functionality
- **TestCLIValidateCommand**: Policy validation
- **TestCLIPolicyCommands**: Policy management commands
- **TestAnalyzerIntegration**: Analyzer component integration
- **TestConcurrentAnalysis**: Concurrent file processing
- **TestPerformance**: Performance with large files

### Test Data

Integration tests use data from `tests/integration/testdata/`:

- **terraform/**: Sample Terraform configurations
  - `secure.tf`: Configuration with no violations
  - `insecure.tf`: Configuration with security issues
  
- **policies/**: Test policies
  - `test_policy.rego`: Simple policy for testing

## Test Coverage

### Generating Coverage Reports

```bash
# Generate coverage for all packages
go test ./... -coverprofile=coverage.out

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html

# View coverage in terminal
go tool cover -func=coverage.out
```

### Coverage Goals

- **Critical Components**: >80% coverage
  - Parser, Analyzer, Policy Engine
- **Supporting Components**: >60% coverage  
  - Reporters, Logger, Utilities
- **Integration**: >70% coverage
  - End-to-end scenarios

## Manual Testing

### Test Release Setup

Use the automated test script:

```bash
# Run comprehensive release testing
./scripts/test-release.sh
```

This script tests:
- Go module setup and dependencies
- Multi-platform builds
- Binary functionality
- Policy validation
- Terraform and OpenTofu scanning
- Multiple output formats

### Manual CLI Testing

```bash
# Test policy validation
./policyguard validate policies/

# Test Terraform scanning
./policyguard scan examples/terraform/insecure_s3.tf

# Test OpenTofu scanning  
./policyguard scan examples/opentofu/s3_insecure.tofu

# Test different output formats
./policyguard scan examples/terraform/ -f json
./policyguard scan examples/terraform/ -f sarif
./policyguard scan examples/terraform/ -f junit

# Test policy commands
./policyguard policy list
./policyguard policy show s3_bucket_encryption
```

### Testing Error Handling

```bash
# Test with invalid Terraform file
echo "invalid { syntax" > test.tf
./policyguard scan test.tf

# Test with non-existent directory
./policyguard scan /non/existent/path

# Test with invalid policy
./policyguard validate /invalid/policy/path
```

## Error Handling & Logging

### Testing Logging Functionality

Run the logger demo to see error handling and logging in action:

```bash
go run examples/logger_demo.go
```

This demonstrates:
- Different log levels (Debug, Info, Warn, Error)
- Log level filtering
- Component-specific loggers with prefixes
- Formatted logging with timestamps
- Error handling patterns

### Log Levels in Testing

```bash
# Test with debug logging
./policyguard scan examples/terraform/ -v

# Test with different log levels
LOG_LEVEL=debug ./policyguard scan examples/terraform/
LOG_LEVEL=error ./policyguard scan examples/terraform/
```

### Error Handling Best Practices

1. **Always wrap errors with context**:
   ```go
   return fmt.Errorf("failed to parse %s: %w", file, err)
   ```

2. **Use appropriate log levels**:
   - Debug: Detailed trace information
   - Info: Normal operation messages
   - Warn: Recoverable issues
   - Error: Failures requiring attention

3. **Component-specific logging**:
   ```go
   parserLog := log.WithPrefix("PARSER")
   policyLog := log.WithPrefix("POLICY")
   reportLog := log.WithPrefix("REPORT")
   ```

## Performance Testing

### Benchmarking

```bash
# Run performance benchmarks
go test -bench=. ./...

# Run with memory profiling
go test -bench=. -memprofile=mem.prof ./...

# Run with CPU profiling
go test -bench=. -cpuprofile=cpu.prof ./...
```

### Large File Testing

```bash
# Test with large Terraform configurations
./policyguard scan /path/to/large/terraform/project

# Test concurrent processing
./policyguard scan examples/terraform/ examples/opentofu/
```

## Adding New Tests

### Unit Tests

1. Create test file with `_test.go` suffix
2. Follow naming convention: `TestFunctionName`
3. Use table-driven tests for multiple scenarios
4. Test both success and failure cases

```go
func TestNewFunction(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"valid input", "test", "expected", false},
        {"invalid input", "", "", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := NewFunction(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("NewFunction() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if result != tt.expected {
                t.Errorf("NewFunction() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Integration Tests

1. Add test to `tests/integration/integration_test.go`
2. Use build tag `// +build integration`
3. Create test data in `testdata/` directory
4. Test complete workflows

```go
//go:build integration

func TestNewIntegrationScenario(t *testing.T) {
    // Test implementation
}
```

## Continuous Integration

Tests run automatically in GitHub Actions:

- **CI Workflow** (`ci.yml`): Unit tests on multiple platforms
- **Release Workflow** (`release.yml`): Full test suite before release
- **Security Workflow** (`policyguard.yml`): Security scanning

### Test Commands in CI

```bash
# Unit tests with coverage
go test -v -race -coverprofile=coverage.out ./...

# Integration tests
go test -v -tags=integration ./tests/integration/

# Security scanning
gosec -fmt sarif -out gosec-results.sarif ./...
```

## Test Dependencies

Ensure these are available for testing:

- Go 1.21+ 
- Make (for Makefile commands)
- jq (for JSON validation in tests)
- All dependencies from `go.mod`

## Troubleshooting Tests

### Common Issues

1. **Import cycle errors**: Check package dependencies
2. **Missing test data**: Ensure `testdata/` files exist
3. **Permission errors**: Check file permissions for test files
4. **Timeout errors**: Increase test timeout for slow operations

### Debug Test Failures

```bash
# Run specific failing test with verbose output
go test -v -run TestSpecificFunction ./pkg/component

# Run with race detection
go test -race ./...

# Run with short flag to skip long-running tests
go test -short ./...
```