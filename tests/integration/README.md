# PolicyGuard Integration Tests

This directory contains integration tests that verify the complete PolicyGuard pipeline from parsing Terraform files to generating security reports.

## Test Coverage

The integration tests cover:

1. **Full Pipeline Testing**
   - Parsing Terraform configurations
   - Loading and evaluating OPA policies
   - Generating reports in multiple formats
   - Verifying correct violation detection

2. **CLI Command Testing**
   - `scan` command with various options
   - `validate` command for policy validation
   - `policy list` and `policy show` commands
   - Error handling and edge cases

3. **Component Integration**
   - Analyzer component integration
   - Parser, Policy Engine, and Reporter working together
   - Concurrent analysis of multiple files

4. **Performance Testing**
   - Large file analysis
   - Concurrent processing
   - Resource usage

## Running Tests

### Run all integration tests:
```bash
make integration-test
```

### Run specific test:
```bash
go test -v -tags=integration -run TestFullPipeline ./tests/integration/
```

### Run with coverage:
```bash
go test -v -tags=integration -cover ./tests/integration/
```

### Run all tests (unit + integration):
```bash
make test-all
```

## Test Data

The `testdata/` directory contains:

- **terraform/**: Sample Terraform configurations
  - `secure.tf`: Configuration with no violations
  - `insecure.tf`: Configuration with multiple security issues
  
- **policies/**: Test policies
  - `test_policy.rego`: Simple policy for testing

## Test Structure

- **TestFullPipeline**: Tests the complete analysis pipeline
- **TestCLIScanCommand**: Tests the CLI scan command
- **TestCLIValidateCommand**: Tests policy validation
- **TestCLIPolicyCommands**: Tests policy management commands
- **TestAnalyzerIntegration**: Tests the analyzer component
- **TestConcurrentAnalysis**: Tests concurrent file analysis
- **TestPerformance**: Tests performance with large files

## Adding New Tests

To add a new integration test:

1. Create test data files in `testdata/`
2. Add test function with `Test` prefix
3. Use the build tag `// +build integration`
4. Test both success and failure scenarios

Example:
```go
func TestNewFeature(t *testing.T) {
    // Test implementation
}
```

## Debugging

To see detailed output:
```bash
go test -v -tags=integration ./tests/integration/
```

To run a specific test with more verbosity:
```bash
go test -v -tags=integration -run TestCLIScanCommand ./tests/integration/
```