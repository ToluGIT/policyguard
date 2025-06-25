// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ToluGIT/policyguard/pkg/analyzer"
	"github.com/ToluGIT/policyguard/pkg/parser/terraform"
	"github.com/ToluGIT/policyguard/pkg/policy/opa"
	"github.com/ToluGIT/policyguard/pkg/reporter/human"
	jsonreporter "github.com/ToluGIT/policyguard/pkg/reporter/json"
	"github.com/ToluGIT/policyguard/pkg/types"
)

func TestMain(m *testing.M) {
	// Build the binary before running tests
	if err := buildBinary(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build binary: %v\n", err)
		os.Exit(1)
	}
	
	code := m.Run()
	
	// Clean up
	os.Remove(getBinaryPath())
	
	os.Exit(code)
}

func buildBinary() error {
	_, currentFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(currentFile), "../..")
	binaryPath := getBinaryPath()
	
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/policyguard")
	cmd.Dir = projectRoot
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed: %v\nOutput: %s", err, output)
	}
	
	return nil
}

func getBinaryPath() string {
	return filepath.Join(os.TempDir(), "policyguard-test")
}

func getTestDataPath(path string) string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "testdata", path)
}

// TestFullPipeline tests the complete analysis pipeline
func TestFullPipeline(t *testing.T) {
	ctx := context.Background()
	
	// Create components
	parser := terraform.New()
	engine := opa.New()
	humanReporter := human.New()
	jsonReporter := jsonreporter.New()
	
	// Load test policies
	policyPath := getTestDataPath("policies")
	err := engine.LoadPoliciesFromDirectory(ctx, policyPath)
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}
	
	tests := []struct {
		name              string
		terraformFile     string
		expectViolations  bool
		minViolations     int
		expectSeverities  []string
	}{
		{
			name:             "secure configuration",
			terraformFile:    "terraform/secure.tf",
			expectViolations: false,
			minViolations:    0,
		},
		{
			name:             "insecure configuration",
			terraformFile:    "terraform/insecure.tf",
			expectViolations: true,
			minViolations:    1,
			expectSeverities: []string{"critical"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse Terraform file
			tfPath := getTestDataPath(tt.terraformFile)
			resources, err := parser.Parse(ctx, tfPath)
			if err != nil {
				t.Fatalf("Failed to parse Terraform file: %v", err)
			}
			
			if len(resources) == 0 {
				t.Fatal("No resources parsed from Terraform file")
			}
			
			// Evaluate policies
			result, err := engine.Evaluate(ctx, resources)
			if err != nil {
				t.Fatalf("Failed to evaluate policies: %v", err)
			}
			
			// Check violations
			if tt.expectViolations {
				if len(result.Violations) < tt.minViolations {
					t.Errorf("Expected at least %d violations, got %d", tt.minViolations, len(result.Violations))
				}
				
				// Check for expected severities
				severityFound := make(map[string]bool)
				for _, v := range result.Violations {
					severityFound[v.Severity] = true
				}
				
				for _, expectedSev := range tt.expectSeverities {
					if !severityFound[expectedSev] {
						t.Errorf("Expected to find violation with severity %s", expectedSev)
					}
				}
			} else {
				if len(result.Violations) > 0 {
					t.Errorf("Expected no violations, got %d", len(result.Violations))
					for _, v := range result.Violations {
						t.Logf("Unexpected violation: %s", v.Message)
					}
				}
			}
			
			// Test human reporter
			humanBuf := &bytes.Buffer{}
			report, err := humanReporter.Generate(ctx, result, resources)
			if err != nil {
				t.Fatalf("Failed to generate human report: %v", err)
			}
			
			err = humanReporter.Write(ctx, report, humanBuf)
			if err != nil {
				t.Fatalf("Failed to write human report: %v", err)
			}
			
			if humanBuf.Len() == 0 {
				t.Error("Human report is empty")
			}
			
			// Test JSON reporter
			jsonBuf := &bytes.Buffer{}
			jsonReport, err := jsonReporter.Generate(ctx, result, resources)
			if err != nil {
				t.Fatalf("Failed to generate JSON report: %v", err)
			}
			
			err = jsonReporter.Write(ctx, jsonReport, jsonBuf)
			if err != nil {
				t.Fatalf("Failed to write JSON report: %v", err)
			}
			
			// Validate JSON output
			var parsedReport types.Report
			err = json.Unmarshal(jsonBuf.Bytes(), &parsedReport)
			if err != nil {
				t.Fatalf("Failed to parse JSON report: %v", err)
			}
			
			if parsedReport.Summary.TotalResources != len(resources) {
				t.Errorf("JSON report resource count mismatch: expected %d, got %d", 
					len(resources), parsedReport.Summary.TotalResources)
			}
		})
	}
}

// TestCLIScanCommand tests the CLI scan command
func TestCLIScanCommand(t *testing.T) {
	binaryPath := getBinaryPath()
	
	tests := []struct {
		name         string
		args         []string
		expectError  bool
		checkOutput  func(t *testing.T, output string)
	}{
		{
			name: "scan secure file",
			args: []string{"scan", getTestDataPath("terraform/secure.tf"), "--policy", filepath.Join(filepath.Dir(getTestDataPath("")), "..", "..", "policies")},
			expectError: false,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "Total Resources Scanned:") {
					t.Error("Output missing resource count")
				}
				if !strings.Contains(output, "Total Violations Found:") {
					t.Error("Output missing violation count")
				}
			},
		},
		{
			name: "scan insecure file",
			args: []string{"scan", getTestDataPath("terraform/insecure.tf"), "--policy", filepath.Join(filepath.Dir(getTestDataPath("")), "..", "..", "policies")},
			expectError: false,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "VIOLATIONS") {
					t.Error("Output missing violations section")
				}
			},
		},
		{
			name: "scan with JSON output",
			args: []string{"scan", getTestDataPath("terraform/secure.tf"), "--format", "json", "--policy", filepath.Join(filepath.Dir(getTestDataPath("")), "..", "..", "policies")},
			expectError: false,
			checkOutput: func(t *testing.T, output string) {
				var report types.Report
				err := json.Unmarshal([]byte(output), &report)
				if err != nil {
					t.Errorf("Failed to parse JSON output: %v", err)
				}
			},
		},
		{
			name: "scan with fail-on-error",
			args: []string{"scan", getTestDataPath("terraform/insecure.tf"), "--fail-on-error", "--policy", getTestDataPath("policies")},
			expectError: true,
		},
		{
			name: "scan non-existent file",
			args: []string{"scan", "/non/existent/file.tf"},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			output, err := cmd.CombinedOutput()
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none. Output: %s", output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v\nOutput: %s", err, output)
				}
			}
			
			if tt.checkOutput != nil {
				tt.checkOutput(t, string(output))
			}
		})
	}
}

// TestCLIValidateCommand tests the CLI validate command
func TestCLIValidateCommand(t *testing.T) {
	binaryPath := getBinaryPath()
	
	// Create an invalid policy for testing
	invalidPolicyPath := filepath.Join(os.TempDir(), "invalid_policy.rego")
	invalidPolicy := `package invalid
	
	# This is invalid Rego syntax
	deny[msg] {
		invalid syntax here
	}`
	
	err := ioutil.WriteFile(invalidPolicyPath, []byte(invalidPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid policy file: %v", err)
	}
	defer os.Remove(invalidPolicyPath)
	
	tests := []struct {
		name        string
		args        []string
		expectError bool
		checkOutput func(t *testing.T, output string)
	}{
		{
			name: "validate valid policies",
			args: []string{"validate", getTestDataPath("policies")},
			expectError: false,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "All policies are valid") {
					t.Error("Expected success message")
				}
			},
		},
		{
			name: "validate invalid policy",
			args: []string{"validate", invalidPolicyPath},
			expectError: true,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "Error:") {
					t.Error("Expected error message")
				}
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			output, err := cmd.CombinedOutput()
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none. Output: %s", output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v\nOutput: %s", err, output)
				}
			}
			
			if tt.checkOutput != nil {
				tt.checkOutput(t, string(output))
			}
		})
	}
}

// TestCLIPolicyCommands tests the policy list and show commands
func TestCLIPolicyCommands(t *testing.T) {
	binaryPath := getBinaryPath()
	
	t.Run("policy list", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "policy", "list", "--policy", getTestDataPath("policies"))
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			t.Fatalf("Failed to list policies: %v\nOutput: %s", err, output)
		}
		
		if !strings.Contains(string(output), "Available policies") {
			t.Error("Output missing policies header")
		}
		
		// Test JSON format
		cmd = exec.Command(binaryPath, "policy", "list", "--policy", getTestDataPath("policies"), "--format", "json")
		output, err = cmd.CombinedOutput()
		
		if err != nil {
			t.Fatalf("Failed to list policies in JSON: %v\nOutput: %s", err, output)
		}
		
		var policies []interface{}
		err = json.Unmarshal(output, &policies)
		if err != nil {
			t.Errorf("Failed to parse JSON output: %v", err)
		}
	})
	
	t.Run("policy show", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "policy", "show", "test_policy", "--policy", getTestDataPath("policies"))
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			t.Fatalf("Failed to show policy: %v\nOutput: %s", err, output)
		}
		
		if !strings.Contains(string(output), "Policy: test_policy") {
			t.Error("Output missing policy details")
		}
		
		// Test raw format
		cmd = exec.Command(binaryPath, "policy", "show", "test_policy", "--policy", getTestDataPath("policies"), "--format", "raw")
		output, err = cmd.CombinedOutput()
		
		if err != nil {
			t.Fatalf("Failed to show policy in raw format: %v\nOutput: %s", err, output)
		}
		
		if !strings.Contains(string(output), "package policyguard") {
			t.Error("Raw output missing policy content")
		}
	})
}

// TestAnalyzerIntegration tests the analyzer component integration
func TestAnalyzerIntegration(t *testing.T) {
	ctx := context.Background()
	
	// Create components
	parser := terraform.New()
	engine := opa.New()
	reporter := human.New()
	
	// Load policies
	err := engine.LoadPoliciesFromDirectory(ctx, getTestDataPath("policies"))
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}
	
	// Create analyzer
	analyzer := analyzer.New(parser, engine, nil, reporter)
	
	// Test file analysis
	t.Run("analyze file", func(t *testing.T) {
		report, err := analyzer.AnalyzeFile(ctx, getTestDataPath("terraform/insecure.tf"))
		if err != nil {
			t.Fatalf("Failed to analyze file: %v", err)
		}
		
		if report.Summary.TotalResources == 0 {
			t.Error("No resources found in analysis")
		}
		
		if report.Summary.TotalViolations == 0 {
			t.Error("Expected violations but found none")
		}
	})
	
	// Test directory analysis
	t.Run("analyze directory", func(t *testing.T) {
		report, err := analyzer.AnalyzeDirectory(ctx, getTestDataPath("terraform"))
		if err != nil {
			t.Fatalf("Failed to analyze directory: %v", err)
		}
		
		// Should have resources from both files
		if report.Summary.TotalResources < 2 {
			t.Error("Expected resources from multiple files")
		}
	})
}

// TestConcurrentAnalysis tests concurrent analysis of multiple files
func TestConcurrentAnalysis(t *testing.T) {
	ctx := context.Background()
	
	// Create components
	parser := terraform.New()
	engine := opa.New()
	reporter := human.New()
	
	// Load policies
	err := engine.LoadPoliciesFromDirectory(ctx, getTestDataPath("policies"))
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}
	
	// Create analyzer
	analyzer := analyzer.New(parser, engine, nil, reporter)
	
	// Analyze multiple files concurrently
	files := []string{
		getTestDataPath("terraform/secure.tf"),
		getTestDataPath("terraform/insecure.tf"),
	}
	
	type result struct {
		file   string
		report *types.Report
		err    error
	}
	
	results := make(chan result, len(files))
	
	for _, file := range files {
		go func(f string) {
			report, err := analyzer.AnalyzeFile(ctx, f)
			results <- result{file: f, report: report, err: err}
		}(file)
	}
	
	// Collect results
	for i := 0; i < len(files); i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("Failed to analyze %s: %v", r.file, r.err)
			} else if r.report == nil {
				t.Errorf("No report generated for %s", r.file)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for analysis results")
		}
	}
}

// TestPerformance tests performance with larger files
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	
	// Create a larger test file
	largeTfPath := filepath.Join(os.TempDir(), "large_test.tf")
	defer os.Remove(largeTfPath)
	
	// Generate a file with many resources
	var content strings.Builder
	for i := 0; i < 100; i++ {
		content.WriteString(fmt.Sprintf(`
resource "aws_s3_bucket" "bucket_%d" {
  bucket = "test-bucket-%d"
  acl    = "public-read"
}

resource "aws_instance" "instance_%d" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  associate_public_ip_address = true
  
  root_block_device {
    encrypted = false
  }
}
`, i, i, i))
	}
	
	err := ioutil.WriteFile(largeTfPath, []byte(content.String()), 0644)
	if err != nil {
		t.Fatalf("Failed to create large test file: %v", err)
	}
	
	// Measure analysis time
	start := time.Now()
	
	cmd := exec.Command(getBinaryPath(), "scan", largeTfPath, "--policy", filepath.Join(filepath.Dir(getTestDataPath("")), "..", "..", "policies"))
	output, err := cmd.CombinedOutput()
	
	duration := time.Since(start)
	
	if err != nil {
		t.Fatalf("Failed to analyze large file: %v\nOutput: %s", err, output)
	}
	
	t.Logf("Analyzed 200 resources in %v", duration)
	
	// Check that it completed within reasonable time
	if duration > 30*time.Second {
		t.Errorf("Analysis took too long: %v", duration)
	}
	
	// Verify results
	if !strings.Contains(string(output), "Total Resources Scanned: 200") {
		t.Error("Expected 200 resources in output")
	}
}