package human

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter implements the reporter.Reporter interface for human-readable output
type Reporter struct{}

// New creates a new human-readable reporter
func New() *Reporter {
	return &Reporter{}
}

// Generate creates a report from policy results
func (r *Reporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	report := &types.Report{
		ID:        fmt.Sprintf("report-%d", time.Now().Unix()),
		Timestamp: time.Now(),
		Resources: resources,
		Violations: result.Violations,
		Metadata:  result.Metadata,
	}

	// Calculate summary
	violationsBySeverity := make(map[string]int)
	for _, v := range result.Violations {
		violationsBySeverity[v.Severity]++
	}

	// Calculate pass rate based on resources with violations (not total violations)
	// This gives a more accurate representation: what percentage of resources are clean?
	resourcesWithViolations := r.countResourcesWithViolations(result.Violations)
	var passRate float64
	if len(resources) > 0 {
		passRate = float64(len(resources)-resourcesWithViolations) / float64(len(resources)) * 100
	} else {
		passRate = 100 // No resources means 100% pass rate
	}

	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             passRate,
	}

	return report, nil
}

// Write writes the report to the given writer in human-readable format
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	// Header
	fmt.Fprintf(writer, "\n%s\n", strings.Repeat("=", 80))
	fmt.Fprintf(writer, "PolicyGuard Security Report\n")
	fmt.Fprintf(writer, "Generated: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "%s\n\n", strings.Repeat("=", 80))

	// Summary
	fmt.Fprintf(writer, "SUMMARY\n")
	fmt.Fprintf(writer, "%s\n", strings.Repeat("-", 40))
	fmt.Fprintf(writer, "Total Resources Scanned: %d\n", report.Summary.TotalResources)
	fmt.Fprintf(writer, "Total Violations Found:  %d\n", report.Summary.TotalViolations)
	fmt.Fprintf(writer, "Pass Rate:               %.1f%%\n\n", report.Summary.PassRate)

	// Violations by severity
	if len(report.Summary.ViolationsBySeverity) > 0 {
		fmt.Fprintf(writer, "Violations by Severity:\n")
		for _, severity := range []string{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
			if count, ok := report.Summary.ViolationsBySeverity[severity]; ok && count > 0 {
				fmt.Fprintf(writer, "  %-10s %d\n", strings.ToUpper(severity)+":", count)
			}
		}
		fmt.Fprintln(writer)
	}

	// No violations found
	if len(report.Violations) == 0 {
		fmt.Fprintf(writer, "No security violations found!\n\n")
		return nil
	}

	// Violations detail
	fmt.Fprintf(writer, "VIOLATIONS\n")
	fmt.Fprintf(writer, "%s\n\n", strings.Repeat("-", 40))

	// Group violations by severity
	violationsBySeverity := make(map[string][]types.PolicyViolation)
	for _, v := range report.Violations {
		violationsBySeverity[v.Severity] = append(violationsBySeverity[v.Severity], v)
	}

	// Display violations by severity
	for _, severity := range []string{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
		violations, ok := violationsBySeverity[severity]
		if !ok || len(violations) == 0 {
			continue
		}

		fmt.Fprintf(writer, "[%s]\n", strings.ToUpper(severity))
		for i, v := range violations {
			r.writeViolation(writer, v, i+1)
		}
		fmt.Fprintln(writer)
	}

	// Footer
	fmt.Fprintf(writer, "%s\n", strings.Repeat("=", 80))
	fmt.Fprintf(writer, "Run 'policyguard scan --help' for more options\n\n")

	return nil
}

// writeViolation writes a single violation in human-readable format
func (r *Reporter) writeViolation(writer io.Writer, violation types.PolicyViolation, index int) {
	fmt.Fprintf(writer, "\n%d. %s\n", index, violation.Message)
	fmt.Fprintf(writer, "   Resource: %s\n", violation.ResourceID)
	fmt.Fprintf(writer, "   Location: %s:%d:%d\n", violation.Location.File, violation.Location.Line, violation.Location.Column)
	fmt.Fprintf(writer, "   Policy:   %s\n", violation.PolicyID)
	
	if violation.Details != "" {
		fmt.Fprintf(writer, "   Details:  %s\n", violation.Details)
	}
	
	if violation.Remediation != "" {
		fmt.Fprintf(writer, "   Fix:      %s\n", violation.Remediation)
	}
}

// countResourcesWithViolations counts the number of unique resources that have at least one violation
func (r *Reporter) countResourcesWithViolations(violations []types.PolicyViolation) int {
	resourcesWithViolations := make(map[string]bool)
	for _, violation := range violations {
		resourcesWithViolations[violation.ResourceID] = true
	}
	return len(resourcesWithViolations)
}

// Format returns the format this reporter outputs
func (r *Reporter) Format() string {
	return "human"
}