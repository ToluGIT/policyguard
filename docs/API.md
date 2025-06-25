# API Documentation

This document describes the PolicyGuard API for programmatic usage and integration.

## Table of Contents

- [Overview](#overview)
- [Core Components](#core-components)
- [Parser API](#parser-api)
- [Policy Engine API](#policy-engine-api)
- [Reporter API](#reporter-api)
- [Analyzer API](#analyzer-api)
- [Types](#types)
- [Examples](#examples)

## Overview

PolicyGuard provides a Go API that can be integrated into other tools and services. The API is organized into several packages:

- `parser`: Parse IaC files into resources
- `policy`: Evaluate resources against policies
- `reporter`: Generate reports in various formats
- `analyzer`: Orchestrate the analysis workflow
- `types`: Common data structures

## Core Components

### Import the Packages

```go
import (
    "github.com/policyguard/policyguard/pkg/analyzer"
    "github.com/policyguard/policyguard/pkg/parser/terraform"
    "github.com/policyguard/policyguard/pkg/policy/opa"
    "github.com/policyguard/policyguard/pkg/reporter/human"
    "github.com/policyguard/policyguard/pkg/reporter/json"
    "github.com/policyguard/policyguard/pkg/types"
)
```

## Parser API

### Parser Interface

```go
type Parser interface {
    // Parse parses the given file and returns extracted resources
    Parse(ctx context.Context, filePath string) ([]types.Resource, error)
    
    // ParseDirectory parses all compatible files in a directory
    ParseDirectory(ctx context.Context, dirPath string) ([]types.Resource, error)
    
    // SupportedExtensions returns the file extensions this parser supports
    SupportedExtensions() []string
}
```

### Terraform Parser

```go
// Create a new Terraform parser
parser := terraform.New()

// Parse a single file
resources, err := parser.Parse(context.Background(), "main.tf")
if err != nil {
    log.Fatal(err)
}

// Parse a directory
resources, err := parser.ParseDirectory(context.Background(), "./terraform")
if err != nil {
    log.Fatal(err)
}

// Check supported extensions
extensions := parser.SupportedExtensions() // [".tf", ".tf.json"]
```

### Parser Factory

```go
// Create parser factory
factory := parser.NewFactory()

// Register parsers
tfParser := terraform.New()
factory.RegisterParser("terraform", tfParser)

// Get parser by type
parser, err := factory.GetParser("terraform")

// Get parser by file extension
parser, err := factory.GetParserByExtension(".tf")
```

## Policy Engine API

### Engine Interface

```go
type Engine interface {
    // Evaluate evaluates resources against loaded policies
    Evaluate(ctx context.Context, resources []types.Resource) (*types.PolicyResult, error)
    
    // LoadPolicy loads a policy from the given path
    LoadPolicy(ctx context.Context, policyPath string) error
    
    // LoadPoliciesFromDirectory loads all policies from a directory
    LoadPoliciesFromDirectory(ctx context.Context, dirPath string) error
    
    // GetLoadedPolicies returns the IDs of all loaded policies
    GetLoadedPolicies() []string
}
```

### OPA Engine Usage

```go
// Create OPA engine
engine := opa.New()

// Load a single policy
err := engine.LoadPolicy(context.Background(), "policies/s3_encryption.rego")
if err != nil {
    log.Fatal(err)
}

// Load all policies from directory
err = engine.LoadPoliciesFromDirectory(context.Background(), "policies/")
if err != nil {
    log.Fatal(err)
}

// Evaluate resources
result, err := engine.Evaluate(context.Background(), resources)
if err != nil {
    log.Fatal(err)
}

// Check results
if result.Passed {
    fmt.Println("All policies passed!")
} else {
    fmt.Printf("Found %d violations\n", len(result.Violations))
}
```

## Reporter API

### Reporter Interface

```go
type Reporter interface {
    // Generate creates a report from policy results
    Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error)
    
    // Write writes the report to the given writer
    Write(ctx context.Context, report *types.Report, writer io.Writer) error
    
    // Format returns the format this reporter outputs
    Format() string
}
```

### Human Reporter

```go
// Create human-readable reporter
reporter := human.New()

// Generate report
report, err := reporter.Generate(context.Background(), result, resources)
if err != nil {
    log.Fatal(err)
}

// Write to stdout
err = reporter.Write(context.Background(), report, os.Stdout)

// Write to file
file, _ := os.Create("report.txt")
defer file.Close()
err = reporter.Write(context.Background(), report, file)
```

### JSON Reporter

```go
// Create JSON reporter
reporter := json.New()

// Generate and write JSON report
report, _ := reporter.Generate(context.Background(), result, resources)
err = reporter.Write(context.Background(), report, os.Stdout)

// Parse JSON output
var reportData types.Report
output := &bytes.Buffer{}
reporter.Write(context.Background(), report, output)
json.Unmarshal(output.Bytes(), &reportData)
```

## Analyzer API

### Analyzer Usage

```go
// Create components
parser := terraform.New()
engine := opa.New()
reporter := human.New()

// Create analyzer
analyzer := analyzer.New(parser, engine, nil, reporter)

// Analyze a file
report, err := analyzer.AnalyzeFile(context.Background(), "main.tf")
if err != nil {
    log.Fatal(err)
}

// Analyze a directory
report, err := analyzer.AnalyzeDirectory(context.Background(), "./terraform")
if err != nil {
    log.Fatal(err)
}

// Check report
fmt.Printf("Scanned %d resources\n", report.Summary.TotalResources)
fmt.Printf("Found %d violations\n", report.Summary.TotalViolations)
```

### Custom Analyzer Configuration

```go
// Create analyzer with custom components
parser := terraform.New()
engine := opa.New()
suggester := remediation.NewBasicSuggester()
reporter := json.New()

analyzer := analyzer.New(parser, engine, suggester, reporter)

// Configure analyzer
config := analyzer.Config{
    PolicyPaths:     []string{"policies/", "custom-policies/"},
    FailOnViolation: true,
}
```

## Types

### Resource

```go
type Resource struct {
    ID         string                 `json:"id"`
    Type       string                 `json:"type"`
    Provider   string                 `json:"provider"`
    Name       string                 `json:"name"`
    Attributes map[string]interface{} `json:"attributes"`
    Location   Location               `json:"location"`
}

type Location struct {
    File   string `json:"file"`
    Line   int    `json:"line"`
    Column int    `json:"column"`
}
```

### PolicyViolation

```go
type PolicyViolation struct {
    ID          string    `json:"id"`
    ResourceID  string    `json:"resource_id"`
    PolicyID    string    `json:"policy_id"`
    Severity    string    `json:"severity"`
    Message     string    `json:"message"`
    Details     string    `json:"details"`
    Remediation string    `json:"remediation"`
    Location    Location  `json:"location"`
    Timestamp   time.Time `json:"timestamp"`
}
```

### PolicyResult

```go
type PolicyResult struct {
    Passed     bool              `json:"passed"`
    Violations []PolicyViolation `json:"violations"`
    Metadata   map[string]string `json:"metadata"`
}
```

### Report

```go
type Report struct {
    ID         string                 `json:"id"`
    Timestamp  time.Time              `json:"timestamp"`
    Summary    Summary                `json:"summary"`
    Violations []PolicyViolation      `json:"violations"`
    Resources  []Resource             `json:"resources"`
    Metadata   map[string]interface{} `json:"metadata"`
}

type Summary struct {
    TotalResources       int            `json:"total_resources"`
    TotalViolations      int            `json:"total_violations"`
    ViolationsBySeverity map[string]int `json:"violations_by_severity"`
    PassRate             float64        `json:"pass_rate"`
}
```

## Examples

### Complete Analysis Pipeline

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    
    "github.com/policyguard/policyguard/pkg/analyzer"
    "github.com/policyguard/policyguard/pkg/parser/terraform"
    "github.com/policyguard/policyguard/pkg/policy/opa"
    "github.com/policyguard/policyguard/pkg/reporter/human"
)

func main() {
    ctx := context.Background()
    
    // Create components
    parser := terraform.New()
    engine := opa.New()
    reporter := human.New()
    
    // Load policies
    err := engine.LoadPoliciesFromDirectory(ctx, "policies/")
    if err != nil {
        log.Fatalf("Failed to load policies: %v", err)
    }
    
    // Create analyzer
    analyzer := analyzer.New(parser, engine, nil, reporter)
    
    // Analyze Terraform files
    report, err := analyzer.AnalyzeDirectory(ctx, "./terraform")
    if err != nil {
        log.Fatalf("Analysis failed: %v", err)
    }
    
    // Generate report
    err = reporter.Write(ctx, report, os.Stdout)
    if err != nil {
        log.Fatalf("Failed to write report: %v", err)
    }
    
    // Exit with appropriate code
    if report.Summary.TotalViolations > 0 {
        os.Exit(1)
    }
}
```

### Custom Policy Evaluation

```go
package main

import (
    "context"
    "fmt"
    
    "github.com/policyguard/policyguard/pkg/parser/terraform"
    "github.com/policyguard/policyguard/pkg/policy/opa"
    "github.com/policyguard/policyguard/pkg/types"
)

func analyzeWithCustomPolicy(filePath string, policyContent string) error {
    ctx := context.Background()
    
    // Parse Terraform file
    parser := terraform.New()
    resources, err := parser.Parse(ctx, filePath)
    if err != nil {
        return fmt.Errorf("parse failed: %w", err)
    }
    
    // Create engine and load policy from string
    engine := opa.New()
    err = engine.LoadPolicyFromString(ctx, "custom.rego", policyContent)
    if err != nil {
        return fmt.Errorf("policy load failed: %w", err)
    }
    
    // Evaluate
    result, err := engine.Evaluate(ctx, resources)
    if err != nil {
        return fmt.Errorf("evaluation failed: %w", err)
    }
    
    // Process results
    for _, violation := range result.Violations {
        fmt.Printf("[%s] %s: %s\n", 
            violation.Severity, 
            violation.ResourceID, 
            violation.Message)
    }
    
    return nil
}
```

### Filtering Resources

```go
// Filter resources by type
func filterResourcesByType(resources []types.Resource, resourceType string) []types.Resource {
    var filtered []types.Resource
    for _, r := range resources {
        if r.Type == resourceType {
            filtered = append(filtered, r)
        }
    }
    return filtered
}

// Filter resources by provider
func filterResourcesByProvider(resources []types.Resource, provider string) []types.Resource {
    var filtered []types.Resource
    for _, r := range resources {
        if r.Provider == provider {
            filtered = append(filtered, r)
        }
    }
    return filtered
}

// Example usage
resources, _ := parser.Parse(ctx, "main.tf")
s3Buckets := filterResourcesByType(resources, "aws_s3_bucket")
awsResources := filterResourcesByProvider(resources, "aws")
```

### Custom Reporter

```go
package main

import (
    "context"
    "encoding/csv"
    "fmt"
    "io"
    
    "github.com/policyguard/policyguard/pkg/types"
)

type CSVReporter struct{}

func (r *CSVReporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
    // Standard report generation
    report := &types.Report{
        ID:         fmt.Sprintf("report-%d", time.Now().Unix()),
        Timestamp:  time.Now(),
        Violations: result.Violations,
        Resources:  resources,
        Summary: types.Summary{
            TotalResources:  len(resources),
            TotalViolations: len(result.Violations),
        },
    }
    return report, nil
}

func (r *CSVReporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
    csvWriter := csv.NewWriter(writer)
    defer csvWriter.Flush()
    
    // Write header
    header := []string{"Resource", "Policy", "Severity", "Message", "File", "Line"}
    if err := csvWriter.Write(header); err != nil {
        return err
    }
    
    // Write violations
    for _, v := range report.Violations {
        record := []string{
            v.ResourceID,
            v.PolicyID,
            v.Severity,
            v.Message,
            v.Location.File,
            fmt.Sprintf("%d", v.Location.Line),
        }
        if err := csvWriter.Write(record); err != nil {
            return err
        }
    }
    
    return nil
}

func (r *CSVReporter) Format() string {
    return "csv"
}
```

### Parallel Analysis

```go
func analyzeParallel(files []string) ([]*types.Report, error) {
    var wg sync.WaitGroup
    reports := make([]*types.Report, len(files))
    errors := make([]error, len(files))
    
    for i, file := range files {
        wg.Add(1)
        go func(index int, filePath string) {
            defer wg.Done()
            
            analyzer := createAnalyzer()
            report, err := analyzer.AnalyzeFile(context.Background(), filePath)
            
            reports[index] = report
            errors[index] = err
        }(i, file)
    }
    
    wg.Wait()
    
    // Check for errors
    for i, err := range errors {
        if err != nil {
            return nil, fmt.Errorf("failed to analyze %s: %w", files[i], err)
        }
    }
    
    return reports, nil
}
```

### Integration with Existing Tools

```go
// Integration with Terraform CLI
func runTerraformPlan() error {
    cmd := exec.Command("terraform", "plan", "-out=tfplan")
    return cmd.Run()
}

// Integration with git
func getChangedFiles() ([]string, error) {
    cmd := exec.Command("git", "diff", "--name-only", "HEAD~1", "HEAD")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    
    files := strings.Split(string(output), "\n")
    var tfFiles []string
    for _, file := range files {
        if strings.HasSuffix(file, ".tf") {
            tfFiles = append(tfFiles, file)
        }
    }
    
    return tfFiles, nil
}

// Analyze only changed files
func analyzeChangedFiles() error {
    files, err := getChangedFiles()
    if err != nil {
        return err
    }
    
    if len(files) == 0 {
        fmt.Println("No Terraform files changed")
        return nil
    }
    
    analyzer := createAnalyzer()
    for _, file := range files {
        report, err := analyzer.AnalyzeFile(context.Background(), file)
        if err != nil {
            return err
        }
        
        if report.Summary.TotalViolations > 0 {
            return fmt.Errorf("violations found in %s", file)
        }
    }
    
    return nil
}
```

## Error Handling

All API methods return errors that should be checked:

```go
// Parse with error handling
resources, err := parser.Parse(ctx, "main.tf")
if err != nil {
    switch {
    case errors.Is(err, parser.ErrFileNotFound):
        log.Fatal("File not found")
    case errors.Is(err, parser.ErrInvalidSyntax):
        log.Fatal("Invalid Terraform syntax")
    default:
        log.Fatalf("Unexpected error: %v", err)
    }
}

// Policy evaluation with error handling
result, err := engine.Evaluate(ctx, resources)
if err != nil {
    if errors.Is(err, policy.ErrNoPoliciesLoaded) {
        log.Fatal("No policies loaded")
    }
    log.Fatalf("Evaluation failed: %v", err)
}
```

## Performance Considerations

1. **Reuse Components**: Create parsers, engines, and reporters once and reuse them
2. **Batch Operations**: Use `ParseDirectory` instead of parsing files individually
3. **Concurrent Processing**: Process multiple files in parallel when possible
4. **Policy Caching**: The OPA engine caches compiled policies automatically

## Version Compatibility

The API follows semantic versioning:
- Major version changes may break compatibility
- Minor version changes add functionality without breaking existing code
- Patch versions contain bug fixes only

Check the version:
```go
import "github.com/policyguard/policyguard/pkg/version"

fmt.Printf("PolicyGuard version: %s\n", version.Version)
```