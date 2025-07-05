# Integration Tests

This directory contains integration tests for PolicyGuard that verify the complete pipeline from parsing to reporting.

## Quick Start

```bash
# Run all integration tests
make integration-test

# Run specific integration test
go test -v -tags=integration -run TestFullPipeline ./tests/integration/

# Run with coverage
go test -v -tags=integration -cover ./tests/integration/
```

## What's Tested

- **Full Pipeline**: Terraform/OpenTofu parsing → Policy evaluation → Report generation
- **CLI Commands**: `scan`, `validate`, `policy list/show`
- **Output Formats**: Human, JSON, SARIF, JUnit
- **Error Handling**: Invalid files, missing policies, edge cases
- **Performance**: Large files, concurrent processing

## Test Structure

- **integration_test.go**: Main integration test file
- **testdata/**: Test data (Terraform files, policies)
- **run_tests.sh**: Test runner script

## Complete Testing Guide

📖 **For comprehensive testing documentation, see the main [TESTING.md](../../TESTING.md) file in the project root.**

That document covers:
- Unit testing
- Integration testing  
- Manual testing
- Error handling & logging
- Performance testing
- Coverage reports
- CI/CD testing
- Adding new tests