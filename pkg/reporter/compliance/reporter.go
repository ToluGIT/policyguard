// Package compliance provides a reporter that maps each finding to the
// standardized control(s) it violates, for an audit/compliance audience.
//
// Output is CSV: one row per finding with its resource, policy, severity,
// mapped CWE control(s), and remediation. A finding whose policy has no
// confident control mapping is emitted with "unmapped" rather than a guessed
// control — honesty over coverage theater (see pkg/compliance).
package compliance

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ToluGIT/policyguard/pkg/compliance"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter implements reporter.Reporter, emitting a compliance-oriented CSV.
type Reporter struct{}

// New creates a new compliance reporter.
func New() *Reporter { return &Reporter{} }

// Generate builds the report (same shape as other reporters so the analyzer
// pipeline is unchanged; the control mapping is applied at Write time).
func (r *Reporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	report := &types.Report{
		ID:         fmt.Sprintf("report-%d", time.Now().Unix()),
		Timestamp:  time.Now(),
		Resources:  resources,
		Violations: result.Violations,
		Metadata:   result.Metadata,
	}

	violationsBySeverity := make(map[string]int)
	for _, v := range result.Violations {
		violationsBySeverity[v.Severity]++
	}
	seen := make(map[string]bool)
	for _, v := range result.Violations {
		seen[v.ResourceID] = true
	}
	var passRate float64
	if len(resources) > 0 {
		passRate = float64(len(resources)-len(seen)) / float64(len(resources)) * 100
	} else {
		passRate = 100
	}
	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             passRate,
	}
	return report, nil
}

// csvHeader is the stable column contract for the compliance CSV. Downstream
// tooling (spreadsheets, GRC imports) depends on this order.
var csvHeader = []string{
	"resource", "policy_id", "severity", "cwe", "cwe_title", "message", "remediation",
}

// Write emits the findings as CSV, one row per finding.
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	w := csv.NewWriter(writer)
	if err := w.Write(csvHeader); err != nil {
		return err
	}

	for _, v := range report.Violations {
		cwe, cweTitle := controlColumns(v.PolicyID)
		row := []string{
			v.ResourceID,
			v.PolicyID,
			v.Severity,
			cwe,
			cweTitle,
			v.Message,
			v.Remediation,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}

// controlColumns returns the CWE id(s) and matching title(s) for a policy. An
// unmapped policy returns "unmapped"/"" rather than a fabricated control.
func controlColumns(policyID string) (cwe, title string) {
	cwes := compliance.CWEsFor(policyID)
	if len(cwes) == 0 {
		return "unmapped", ""
	}
	titles := make([]string, 0, len(cwes))
	for _, c := range cwes {
		titles = append(titles, compliance.CWETitle(c))
	}
	return strings.Join(cwes, ";"), strings.Join(titles, ";")
}

// Format returns the format identifier.
func (r *Reporter) Format() string { return "compliance" }
