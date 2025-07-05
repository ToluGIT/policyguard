//go:build ignore

package main

import (
	"fmt"
	"os"
	"time"
	
	"github.com/ToluGIT/policyguard/pkg/logger"
)

func main() {
	fmt.Println("=== PolicyGuard Logger Demo ===")
	fmt.Println()
	
	// Create default logger
	log := logger.Default()
	
	// Demonstrate all log levels
	fmt.Println("1. Demonstrating Log Levels (Debug Level - Shows All):")
	log.SetLevel(logger.DebugLevel)
	log.Debug("Debug: Parsing file structure...")
	log.Info("Info: Starting security analysis")
	log.Warn("Warning: Using default policies")
	log.Error("Error: Policy validation failed")
	
	fmt.Println("\n2. Demonstrating Log Level Filtering (Info Level):")
	log.SetLevel(logger.InfoLevel)
	log.Debug("This debug message won't appear")
	log.Info("Info: Processing Terraform files")
	log.Warn("Warning: Found potential security issue")
	log.Error("Error: Failed to parse resource")
	
	fmt.Println("\n3. Demonstrating Log Level Filtering (Error Level):")
	log.SetLevel(logger.ErrorLevel)
	log.Debug("This debug message won't appear")
	log.Info("This info message won't appear")
	log.Warn("This warning won't appear")
	log.Error("Error: Critical security violation found")
	
	// Demonstrate prefixed loggers for different components
	fmt.Println("\n4. Demonstrating Component-Specific Loggers:")
	log.SetLevel(logger.InfoLevel)
	
	parserLog := log.WithPrefix("PARSER")
	policyLog := log.WithPrefix("POLICY")
	reportLog := log.WithPrefix("REPORT")
	
	parserLog.Info("Loading Terraform configuration files")
	parserLog.Warn("Deprecated syntax detected in main.tf")
	
	policyLog.Info("Evaluating 25 security policies")
	policyLog.Error("Failed to load custom policy: syntax error at line 15")
	
	reportLog.Info("Generating security report")
	reportLog.Info("Found 3 high-severity violations")
	
	// Demonstrate formatted logging
	fmt.Println("\n5. Demonstrating Formatted Logging:")
	
	resources := 42
	violations := 7
	duration := 1.234
	
	log.Info("Analyzed %d resources in %.3f seconds", resources, duration)
	log.Warn("Found %d security violations across %d resources", violations, resources)
	log.Error("Resource '%s' violates policy '%s'", "aws_s3_bucket.public", "s3-public-access")
	
	// Demonstrate error handling patterns
	fmt.Println("\n6. Demonstrating Error Handling Patterns:")
	
	// Simulate file operations with error handling
	filename := "/non/existent/terraform.tf"
	if _, err := os.Open(filename); err != nil {
		log.Error("Failed to open file %s: %v", filename, err)
	}
	
	// Simulate parsing with detailed error context
	parserLog.Debug("Attempting to parse: %s", filename)
	if err := simulateParsing(filename); err != nil {
		parserLog.Error("Parse failed: %v", err)
		parserLog.Debug("Stack trace: %+v", err)
	}
	
	// Demonstrate different severity levels for different scenarios
	fmt.Println("\n7. Demonstrating Severity-Based Logging:")
	
	// Successful operation
	log.Info("Successfully parsed 'main.tf'")
	
	// Minor issue
	log.Warn("Resource 'aws_instance.web' has no tags defined")
	
	// Security concern
	log.Error("Security violation: S3 bucket 'logs' has public read access")
	
	// Parse different log levels from string
	fmt.Println("\n8. Demonstrating Log Level Parsing:")
	levelStrings := []string{"debug", "INFO", "warn", "ERROR", "invalid"}
	
	for _, levelStr := range levelStrings {
		level, err := logger.ParseLevel(levelStr)
		if err != nil {
			fmt.Printf("Failed to parse level '%s': %v\n", levelStr, err)
		} else {
			fmt.Printf("Parsed '%s' as level: %d\n", levelStr, level)
		}
	}
	
	// Demonstrate timestamp in logs
	fmt.Println("\n9. Log Output with Timestamps:")
	log.Info("Logs include timestamps by default")
	time.Sleep(1 * time.Second)
	log.Info("One second later...")
}

func simulateParsing(filename string) error {
	return fmt.Errorf("failed to parse %s: unexpected token at line 10", filename)
}