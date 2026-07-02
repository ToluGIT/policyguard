package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ToluGIT/policyguard/pkg/analyzer"
	"github.com/ToluGIT/policyguard/pkg/config"
	"github.com/ToluGIT/policyguard/pkg/logger"
	"github.com/ToluGIT/policyguard/pkg/parser/terraform"
	"github.com/ToluGIT/policyguard/pkg/policy/opa"
	"github.com/ToluGIT/policyguard/pkg/remediation"
	"github.com/ToluGIT/policyguard/pkg/reporter"
	compliancereporter "github.com/ToluGIT/policyguard/pkg/reporter/compliance"
	htmlreporter "github.com/ToluGIT/policyguard/pkg/reporter/html"
	"github.com/ToluGIT/policyguard/pkg/reporter/human"
	jsonreporter "github.com/ToluGIT/policyguard/pkg/reporter/json"
	junitreporter "github.com/ToluGIT/policyguard/pkg/reporter/junit"
	sarifreporter "github.com/ToluGIT/policyguard/pkg/reporter/sarif"
	"github.com/ToluGIT/policyguard/pkg/web"
	"github.com/spf13/cobra"
)

var (
	version = "0.3.1"
	commit  = "none"
	date    = "unknown"
)

// Exit codes. These form the contract a CI gate relies on: a clean scan, a scan
// that found violations, and a scan that failed to run must be distinguishable.
// Conflating "violations found" with "the scanner broke" lets a misconfigured
// pipeline pass when it should fail (or vice versa).
const (
	exitClean      = 0 // no violations (or violations found without --fail-on-error)
	exitViolations = 1 // violations found and --fail-on-error was set
	exitError      = 2 // the scan could not complete: bad input, unreadable policy, internal error
)

// errViolations is a sentinel returned by the scan command when violations are
// found under --fail-on-error. main() maps it to exitViolations; any other
// (real) error maps to exitError. It carries no message because the report has
// already been written to the user.
var errViolations = errors.New("policy violations found")

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
	// Print to stderr, never stdout: stdout carries the (often machine-readable)
	// report, and a decorative banner there would corrupt JSON/SARIF/JUnit output
	// or any redirected file. stderr keeps the banner visible to an interactive
	// user without polluting the data stream.
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "By ToluBanji - ToluGIT | version: %s\n", version)
	fmt.Fprintln(os.Stderr) // Add a blank line after the banner for better readability
}

func main() {
	// The banner goes to stderr (see printBanner), so it never corrupts a
	// machine-readable report on stdout. We still suppress it for JSON so the
	// common `... -f json | jq` case stays visually clean on a terminal.
	if !isNonInteractiveMode() {
		printBanner()
	}

	if err := newRootCmd().Execute(); err != nil {
		// errViolations means the scan ran fine and found violations under
		// --fail-on-error; the report is already printed, so exit quietly with
		// the violations code. Everything else is a genuine failure to run.
		if errors.Is(err, errViolations) {
			os.Exit(exitViolations)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitError)
	}
}

// isNonInteractiveMode determines if we're running in a non-interactive mode
// where we should skip printing the banner (like JSON output)
func isNonInteractiveMode() bool {
	for _, arg := range os.Args {
		if arg == "--format=json" || arg == "-f=json" || arg == "-f" || arg == "--format" {
			// Check the next argument if this is -f or --format
			if arg == "-f" || arg == "--format" {
				for i, a := range os.Args {
					if a == arg && i < len(os.Args)-1 && os.Args[i+1] == "json" {
						return true
					}
				}
			} else {
				return true
			}
		}
	}
	return false
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
		// main() owns error reporting and exit codes; don't let Cobra print usage
		// or the error itself on a failed run (it would dump usage text on every
		// scan error and double-print, or surface the errViolations sentinel).
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default is $HOME/.policyguard.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	rootCmd.AddCommand(
		newScanCmd(),
		newValidateCmd(),
		newPolicyCmd(),
		newServeCmd(),
	)

	return rootCmd
}

// newServeCmd starts the web GUI: a local server that scans uploaded/pasted
// Terraform and renders the dashboard. Binds to localhost unless --public.
func newServeCmd() *cobra.Command {
	var (
		addr   string
		public bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the web GUI (upload/paste Terraform and scan in the browser)",
		Long: `Start a local web server that hosts the PolicyGuard GUI: import or paste
Terraform/OpenTofu and scan it in the browser, rendered as the dashboard.

By default it binds to localhost only. Pass --public for a hardened mode
(upload/paste only, stricter size and rate limits) suitable for hosting; the
server only ever loads PolicyGuard's trusted built-in policies.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if public && (strings.HasPrefix(addr, "127.0.0.1") || strings.HasPrefix(addr, "localhost")) {
				// In public mode, default to all interfaces so the container/host
				// can map the port; an explicit --addr still wins.
				if !cmd.Flags().Changed("addr") {
					addr = "0.0.0.0:8080"
				}
			}
			srv, err := web.New(web.Config{Addr: addr, Public: public, Version: version})
			if err != nil {
				return err
			}
			mode := "local"
			if public {
				mode = "PUBLIC (upload-only, hardened)"
			}
			fmt.Fprintf(os.Stderr, "PolicyGuard GUI [%s] → http://%s\n", mode, addr)
			return srv.ListenAndServe()
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "address to listen on")
	cmd.Flags().BoolVar(&public, "public", false, "hardened public mode (upload/paste only, stricter limits)")
	return cmd
}

func newScanCmd() *cobra.Command {
	var (
		policyPath         string
		format             string
		output             string
		failOnError        bool
		severityConfigPath string
		suppressConfigPath string
		verbose            bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan IaC files for security issues",
		Long: `Scan Infrastructure as Code files for security issues and policy violations.

Accepts one or more files and/or directories. Multiple paths are scanned
together (a single report), which also lets cross-resource policies see related
resources defined across different files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// Create parser
			tfParser := terraform.New()

			// Set logging level based on verbose flag
			log := logger.Default()
			if verbose {
				log.SetLevel(logger.DebugLevel)
			} else {
				log.SetLevel(logger.InfoLevel)
			}
			tfParser.WithLogger(log)

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
				rep = sarifreporter.NewWithVersion(version)
			case "compliance":
				rep = compliancereporter.New()
			case "html":
				rep = htmlreporter.NewWithVersion(version)
			default:
				rep = human.New()
			}

			// Create analyzer with a remediation suggester so findings carry a
			// corrected-HCL snippet where a template exists.
			policyAnalyzer := analyzer.New(tfParser, policyEngine, remediation.NewBasicSuggester(), rep)

			// Load suppression rules if specified.
			if suppressConfigPath != "" {
				suppressions, err := config.LoadSuppressionConfig(suppressConfigPath)
				if err != nil {
					return fmt.Errorf("failed to load suppression configuration: %w", err)
				}
				// A rule without a resource suppresses the policy for every
				// resource (current and future). Warn so a broad rule is a
				// conscious choice, not a silent one — this hides findings.
				for _, r := range suppressions.Rules {
					if r.Resource == "" {
						log.Warn("suppression for policy %q applies to ALL resources (no resource scope) — new resources will also be suppressed", r.PolicyID)
					}
				}
				policyAnalyzer.WithSuppressions(suppressions)
			}

			// Scan all provided paths together (files and/or directories).
			report, err := policyAnalyzer.AnalyzePaths(ctx, args)
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

			// Signal violations found (under --fail-on-error) via a sentinel error
			// so main() can map it to the dedicated violations exit code, distinct
			// from the error code used when the scan itself fails to run.
			if failOnError && len(report.Violations) > 0 {
				return errViolations
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&policyPath, "policy", "p", "policies/", "path to policy files")
	cmd.Flags().StringVarP(&format, "format", "f", "human", "output format (human, json, junit, sarif, compliance[=CWE CSV], html)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().BoolVar(&failOnError, "fail-on-error", false, "exit with non-zero code on policy violations")
	cmd.Flags().StringVar(&severityConfigPath, "severity-config", "", "path to custom policy severity configuration")
	cmd.Flags().StringVar(&suppressConfigPath, "suppress", "", "path to a suppression configuration (acknowledge findings with a reason)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show verbose debug output")

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
