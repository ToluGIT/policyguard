package json

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter implements the reporter.Reporter interface for JSON output
type Reporter struct {
	pretty bool
}

// New creates a new JSON reporter
func New() *Reporter {
	return &Reporter{
		pretty: true,
	}
}

// NewCompact creates a new JSON reporter with compact output
func NewCompact() *Reporter {
	return &Reporter{
		pretty: false,
	}
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

	passRate := 0.0
	if len(resources) > 0 {
		passRate = float64(len(resources)-len(result.Violations)) / float64(len(resources)) * 100
	}

	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             passRate,
	}

	return report, nil
}

// Write writes the report to the given writer in JSON format
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	if r.pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(report)
}

// Format returns the format this reporter outputs
func (r *Reporter) Format() string {
	return "json"
}