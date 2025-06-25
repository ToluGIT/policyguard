# Testing PolicyGuard

This document explains how to test the unit tests and error handling/logging functionality in PolicyGuard.

## Running Unit Tests

### Run All Tests
```bash
go test ./... -v
```

### Run Tests with Coverage
```bash
go test ./... -v -cover
```

### Run Specific Package Tests
```bash
# Test the parser
go test ./pkg/parser/terraform -v -cover

# Test the logger
go test ./pkg/logger -v -cover

# Test the remediation suggester
go test ./pkg/remediation -v -cover
```

### Generate Coverage Report
```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

## Current Test Coverage

- **Parser (Terraform)**: 78.8% coverage
  - ✅ Parsing S3 buckets, EC2 instances, security groups
  - ✅ Parsing data sources
  - ✅ Error handling for invalid HCL
  - ✅ Directory parsing

- **Logger**: 50.7% coverage
  - ✅ Log level filtering
  - ✅ Formatted output
  - ✅ Component-specific loggers with prefixes
  - ✅ Log level parsing

## Testing Error Handling & Logging

### 1. Run the Logger Demo
```bash
go run examples/logger_demo.go
```

This demonstrates:
- Different log levels (Debug, Info, Warn, Error)
- Log level filtering
- Component-specific loggers with prefixes
- Formatted logging with timestamps
- Error handling patterns

### 2. Key Features Demonstrated

#### Log Levels
- **Debug**: Detailed information for debugging
- **Info**: General informational messages
- **Warn**: Warning messages for potential issues
- **Error**: Error messages for failures

#### Component Prefixes
```go
parserLog := log.WithPrefix("PARSER")
policyLog := log.WithPrefix("POLICY")
reportLog := log.WithPrefix("REPORT")
```

#### Error Handling
```go
if err != nil {
    log.Error("Failed to parse file %s: %v", filename, err)
}
```

### 3. Integration with Components

All components use the logger for consistent error handling:

```go
// Parser error handling
if err != nil {
    return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
}

// Policy engine error handling
if diags.HasErrors() {
    return nil, fmt.Errorf("failed to compile policy: %s", diags.Error())
}

// Analyzer error handling with logging
if err != nil {
    log.Error("Analysis failed: %v", err)
    return nil, err
}
```

## Manual Testing

### Test Parser with Invalid Files
```bash
# Create an invalid Terraform file
echo "invalid { syntax" > test.tf

# Run PolicyGuard scan
./policyguard scan test.tf
```

### Test with Example Files
```bash
# Scan insecure examples
./policyguard scan examples/terraform/insecure_s3.tf
./policyguard scan examples/terraform/insecure_ec2.tf
```

### Test Different Log Levels
```bash
# Run with debug logging
./policyguard scan examples/terraform/ -v

# Run with error-only logging
LOG_LEVEL=error ./policyguard scan examples/terraform/
```

## Error Handling Best Practices

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
   - Each major component has its own logger prefix
   - Makes it easy to trace issues to specific components

4. **Structured error messages**:
   - Include file paths, line numbers, and specific details
   - Provide actionable error messages