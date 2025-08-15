package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ToluGIT/policyguard/pkg/analyzer"
	"github.com/ToluGIT/policyguard/pkg/logger"
	"github.com/ToluGIT/policyguard/pkg/parser/terraform"
	"github.com/ToluGIT/policyguard/pkg/policy/opa"
	"github.com/ToluGIT/policyguard/pkg/reporter"
	"github.com/ToluGIT/policyguard/pkg/reporter/human"
	jsonreporter "github.com/ToluGIT/policyguard/pkg/reporter/json"
	junitreporter "github.com/ToluGIT/policyguard/pkg/reporter/junit"
	sarifreporter "github.com/ToluGIT/policyguard/pkg/reporter/sarif"
	"github.com/ToluGIT/policyguard/pkg/types"
	"github.com/spf13/cobra"
)

var (
	version = "0.3.0"
	commit  = "none"
	date    = "unknown"
)

func printBanner() {
	banner := `
██████╗  ██████╗ ██╗     ██╗ ██████╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██╔═══██╗██║     ██║██╔════╝╚██╗ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝██║   ██║██║     ██║██║      ╚████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═══╝ ██║   ██║██║     ██║██║       ╚██╔╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║     ╚██████╔╝███████╗██║╚██████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝      ╚═════╝ ╚══════╝╚═╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                   Security Policy Scanner for Infrastructure as Code
`
	fmt.Println(banner)
	fmt.Printf("By ToluBanji - ToluGIT | version: %s\n", version)
	
	// Simulate an update check for demonstration purposes
	// This would be replaced with actual update check logic in the future
	latestVersion := "0.3.1"
	if version != latestVersion {
		fmt.Printf("Update available %s -> %s\n", version, latestVersion)
	}
	
	fmt.Println() // Add a blank line after the banner for better readability
}

func main() {
	printBanner()
	
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		configFile string
		verbose    bool
	)

	rootCmd := &cobra.Command{
		Use:   "policyguard",
		Short: "IaC Security Policy Engine",
		Long: `PolicyGuard is a security policy engine for Infrastructure as Code.
It analyzes Terraform configurations and evaluates them against security policies
to identify potential security issues and compliance violations.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default is $HOME/.policyguard.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	rootCmd.AddCommand(
		newScanCmd(),
		newValidateCmd(),
		newPolicyCmd(),
	)

	return rootCmd
}

func newScanCmd() *cobra.Command {
	var (
		policyPath         string
		format             string
		output             string
		failOnError        bool
		severityConfigPath string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan IaC files for security issues",
		Long:  `Scan Infrastructure as Code files for security issues and policy violations.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			targetPath := args[0]

			// Create parser
			tfParser := terraform.New()
			
			// Create policy engine
			policyEngine := opa.New()
			
			// Load severity configuration if specified
			if severityConfigPath != "" {
				if err := policyEngine.WithSeverityConfig(severityConfigPath); err != nil {
					return fmt.Errorf("failed to load severity configuration: %w", err)
				}
			}
			
			// Load policies
			if err := policyEngine.LoadPoliciesFromDirectory(ctx, policyPath); err != nil {
				return fmt.Errorf("failed to load policies: %w", err)
			}

			// Create reporter
			var rep reporter.Reporter
			switch format {
			case "json":
				rep = jsonreporter.New()
			case "junit":
				rep = junitreporter.New()
			case "sarif":
				rep = sarifreporter.New()
			default:
				rep = human.New()
			}

			// Create analyzer
			policyAnalyzer := analyzer.New(tfParser, policyEngine, nil, rep)

			// Determine if target is file or directory
			info, err := os.Stat(targetPath)
			if err != nil {
				return fmt.Errorf("failed to access target path: %w", err)
			}

			var report *types.Report
			if info.IsDir() {
				report, err = policyAnalyzer.AnalyzeDirectory(ctx, targetPath)
			} else {
				report, err = policyAnalyzer.AnalyzeFile(ctx, targetPath)
			}

			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}

			// Output report
			var writer io.Writer = os.Stdout
			if output != "" {
				file, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer file.Close()
				writer = file
			}

			if err := rep.Write(ctx, report, writer); err != nil {
				return fmt.Errorf("failed to write report: %w", err)
			}

			// Exit with error code if violations found and fail-on-error is set
			if failOnError && len(report.Violations) > 0 {
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&policyPath, "policy", "p", "policies/", "path to policy files")
	cmd.Flags().StringVarP(&format, "format", "f", "human", "output format (human, json, junit, sarif)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().BoolVar(&failOnError, "fail-on-error", false, "exit with non-zero code on policy violations")
	cmd.Flags().StringVar(&severityConfigPath, "severity-config", "", "path to custom policy severity configuration")

	return cmd
}

func newValidateCmd() *cobra.Command {
	var (
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate policy files",
		Long:  `Validate that policy files are correctly formatted and contain valid rules.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			policyPath := args[0]
			
			log := logger.Default()
			if verbose {
				log.SetLevel(logger.DebugLevel)
			}
			
			// Create OPA engine for validation
			engine := opa.New()
			
			// Check if path is file or directory
			info, err := os.Stat(policyPath)
			if err != nil {
				return fmt.Errorf("failed to access policy path: %w", err)
			}
			
			var policyFiles []string
			if info.IsDir() {
				// Find all .rego files in directory
				err = filepath.Walk(policyPath, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() && strings.HasSuffix(path, ".rego") {
						policyFiles = append(policyFiles, path)
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("failed to walk directory: %w", err)
				}
			} else {
				policyFiles = []string{policyPath}
			}
			
			if len(policyFiles) == 0 {
				return fmt.Errorf("no policy files found in %s", policyPath)
			}
			
			fmt.Printf("Validating %d policy file(s)...\n\n", len(policyFiles))
			
			hasErrors := false
			for _, file := range policyFiles {
				relPath, _ := filepath.Rel(policyPath, file)
				if relPath == "" {
					relPath = filepath.Base(file)
				}
				
				log.Debug("Validating %s", file)
				
				// Try to load the policy
				err := engine.LoadPolicy(ctx, file)
				if err != nil {
					fmt.Printf("❌ %s\n", relPath)
					fmt.Printf("   Error: %v\n\n", err)
					hasErrors = true
				} else {
					fmt.Printf("✅ %s\n", relPath)
				}
			}
			
			if hasErrors {
				return fmt.Errorf("validation failed: some policies have errors")
			}
			
			fmt.Printf("\n✅ All policies are valid!\n")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	return cmd
}

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage security policies",
		Long:  `Manage security policies including listing, adding, and removing policies.`,
	}

	cmd.AddCommand(
		newPolicyListCmd(),
		newPolicyShowCmd(),
	)

	return cmd
}

func newPolicyListCmd() *cobra.Command {
	var (
		policyPath string
		format     string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Find all .rego files in the policies directory
			var policyFiles []string
			err := filepath.Walk(policyPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && strings.HasSuffix(path, ".rego") {
					policyFiles = append(policyFiles, path)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to list policies: %w", err)
			}
			
			if len(policyFiles) == 0 {
				fmt.Printf("No policies found in %s\n", policyPath)
				return nil
			}
			
			// Parse policy metadata
			type PolicyInfo struct {
				ID          string
				Path        string
				Provider    string
				Resource    string
				RuleCount   int
				Description string
			}
			
			var policies []PolicyInfo
			for _, file := range policyFiles {
				content, err := ioutil.ReadFile(file)
				if err != nil {
					continue
				}
				
				relPath, _ := filepath.Rel(policyPath, file)
				
				// Extract basic info from file path and content
				parts := strings.Split(relPath, string(os.PathSeparator))
				provider := "general"
				if len(parts) > 1 {
					provider = parts[0]
				}
				
				// Count violation rules (check both "violation[" and "deny[" patterns)
				ruleCount := strings.Count(string(content), "violation[") + strings.Count(string(content), "deny[")
				
				// Extract package name and description
				lines := strings.Split(string(content), "\n")
				var description string
				for _, line := range lines {
					if strings.HasPrefix(line, "# Description:") {
						description = strings.TrimPrefix(line, "# Description:")
						description = strings.TrimSpace(description)
						break
					}
				}
				
				baseName := filepath.Base(file)
				policyID := strings.TrimSuffix(baseName, ".rego")
				
				policies = append(policies, PolicyInfo{
					ID:          policyID,
					Path:        relPath,
					Provider:    provider,
					Resource:    strings.Replace(policyID, "_", " ", -1),
					RuleCount:   ruleCount,
					Description: description,
				})
			}
			
			// Sort policies by provider and ID
			sort.Slice(policies, func(i, j int) bool {
				if policies[i].Provider != policies[j].Provider {
					return policies[i].Provider < policies[j].Provider
				}
				return policies[i].ID < policies[j].ID
			})
			
			// Output based on format
			switch format {
			case "json":
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(policies)
			default:
				fmt.Printf("Available policies (%d):\n\n", len(policies))
				
				currentProvider := ""
				for _, policy := range policies {
					if policy.Provider != currentProvider {
						if currentProvider != "" {
							fmt.Println()
						}
						currentProvider = policy.Provider
						fmt.Printf("📁 %s\n", strings.ToUpper(policy.Provider))
						fmt.Println(strings.Repeat("-", 60))
					}
					
					fmt.Printf("  • %s", policy.ID)
					if policy.RuleCount > 0 {
						fmt.Printf(" (%d rules)", policy.RuleCount)
					}
					fmt.Println()
					if policy.Description != "" {
						fmt.Printf("    %s\n", policy.Description)
					}
				}
			}
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&policyPath, "policy", "p", "policies/", "path to policy files")
	cmd.Flags().StringVarP(&format, "format", "f", "human", "output format (human, json)")
	
	return cmd
}

func newPolicyShowCmd() *cobra.Command {
	var (
		policyPath string
		format     string
	)

	cmd := &cobra.Command{
		Use:   "show [policy-id]",
		Short: "Show policy details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policyID := args[0]
			
			// Find the policy file
			var policyFile string
			err := filepath.Walk(policyPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && strings.HasSuffix(path, ".rego") {
					baseName := filepath.Base(path)
					if strings.TrimSuffix(baseName, ".rego") == policyID {
						policyFile = path
						return filepath.SkipDir // Stop walking
					}
				}
				return nil
			})
			
			if err != nil && err != filepath.SkipDir {
				return fmt.Errorf("failed to search for policy: %w", err)
			}
			
			if policyFile == "" {
				return fmt.Errorf("policy '%s' not found", policyID)
			}
			
			// Read policy content
			content, err := ioutil.ReadFile(policyFile)
			if err != nil {
				return fmt.Errorf("failed to read policy file: %w", err)
			}
			
			// Parse policy details
			relPath, _ := filepath.Rel(policyPath, policyFile)
			parts := strings.Split(relPath, string(os.PathSeparator))
			provider := "general"
			if len(parts) > 1 {
				provider = parts[0]
			}
			
			// Extract metadata from content
			lines := strings.Split(string(content), "\n")
			var packageName, description string
			var rules []string
			
			for i, line := range lines {
				line = strings.TrimSpace(line)
				
				// Extract package name
				if strings.HasPrefix(line, "package ") {
					packageName = strings.TrimPrefix(line, "package ")
				}
				
				// Extract description
				if strings.HasPrefix(line, "# Description:") {
					description = strings.TrimPrefix(line, "# Description:")
					description = strings.TrimSpace(description)
				}
				
				// Extract violation rules (check both "violation[" and "deny[" patterns)
				if strings.Contains(line, "violation[") || strings.Contains(line, "deny[") {
					// Try to find the comment above the rule
					for j := i - 1; j >= 0; j-- {
						commentLine := strings.TrimSpace(lines[j])
						if strings.HasPrefix(commentLine, "#") && !strings.HasPrefix(commentLine, "# ") {
							break
						}
						if strings.HasPrefix(commentLine, "# ") {
							ruleName := strings.TrimPrefix(commentLine, "# ")
							rules = append(rules, ruleName)
							break
						}
						if commentLine != "" && !strings.HasPrefix(commentLine, "#") {
							break
						}
					}
				}
			}
			
			// Count total rules (check both "violation[" and "deny[" patterns)
			ruleCount := strings.Count(string(content), "violation[") + strings.Count(string(content), "deny[")
			
			// Output based on format
			switch format {
			case "json":
				policyInfo := map[string]interface{}{
					"id":          policyID,
					"path":        relPath,
					"provider":    provider,
					"package":     packageName,
					"description": description,
					"ruleCount":   ruleCount,
					"rules":       rules,
				}
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(policyInfo)
				
			case "raw":
				fmt.Print(string(content))
				
			default:
				// Human-readable format
				fmt.Printf("Policy: %s\n", policyID)
				fmt.Println(strings.Repeat("=", 60))
				fmt.Printf("Path:     %s\n", relPath)
				fmt.Printf("Provider: %s\n", provider)
				fmt.Printf("Package:  %s\n", packageName)
				
				if description != "" {
					fmt.Printf("\nDescription:\n  %s\n", description)
				}
				
				fmt.Printf("\nRules (%d):\n", ruleCount)
				if len(rules) > 0 {
					for i, rule := range rules {
						fmt.Printf("  %d. %s\n", i+1, rule)
					}
				} else {
					// If we couldn't extract rule names, show a generic message
					fmt.Printf("  This policy contains %d violation rules\n", ruleCount)
				}
				
				fmt.Printf("\nView the full policy with: policyguard policy show %s --format raw\n", policyID)
			}
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&policyPath, "policy", "p", "policies/", "path to policy files")
	cmd.Flags().StringVarP(&format, "format", "f", "human", "output format (human, json, raw)")
	
	return cmd
}