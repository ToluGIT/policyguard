package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter implements the SARIF format reporter
type Reporter struct{}

// New creates a new SARIF reporter
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

	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             float64(len(resources)-len(result.Violations)) / float64(len(resources)) * 100,
	}

	return report, nil
}

// Write writes the report to the given writer in SARIF format
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	sarifReport := r.toSARIF(report)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifReport)
}

// Format returns the format this reporter outputs
func (r *Reporter) Format() string {
	return "sarif"
}

// SARIF structures
type sarifReport struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	ShortDescription sarifText             `json:"shortDescription"`
	FullDescription  sarifText             `json:"fullDescription"`
	Help             sarifText             `json:"help"`
	DefaultConfig    sarifRuleConfig       `json:"defaultConfiguration"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string              `json:"ruleId"`
	Level     string              `json:"level"`
	Message   sarifMessage        `json:"message"`
	Locations []sarifLocation     `json:"locations"`
	Fixes     []sarifFix          `json:"fixes,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifFix struct {
	Description sarifMessage         `json:"description"`
	Changes     []sarifChange        `json:"artifactChanges"`
}

type sarifChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion sarifRegion `json:"deletedRegion"`
	InsertedContent sarifContent `json:"insertedContent"`
}

type sarifContent struct {
	Text string `json:"text"`
}

func (r *Reporter) toSARIF(report *types.Report) *sarifReport {
	// Collect unique rules
	rulesMap := make(map[string]*types.PolicyViolation)
	for _, violation := range report.Violations {
		if _, exists := rulesMap[violation.PolicyID]; !exists {
			rulesMap[violation.PolicyID] = &violation
		}
	}

	// Build rules
	var rules []sarifRule
	for policyID, violation := range rulesMap {
		level := severityToSARIFLevel(violation.Severity)
		rule := sarifRule{
			ID:   policyID,
			Name: policyID,
			ShortDescription: sarifText{
				Text: violation.Message,
			},
			FullDescription: sarifText{
				Text: violation.Details,
			},
			Help: sarifText{
				Text: violation.Remediation,
			},
			DefaultConfig: sarifRuleConfig{
				Level: level,
			},
			Properties: map[string]interface{}{
				"severity": violation.Severity,
				"tags":     []string{"security", "infrastructure-as-code", "terraform"},
			},
		}
		rules = append(rules, rule)
	}

	// Build results
	var results []sarifResult
	for _, violation := range report.Violations {
		result := sarifResult{
			RuleID:  violation.PolicyID,
			Level:   severityToSARIFLevel(violation.Severity),
			Message: sarifMessage{
				Text: violation.Message,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: violation.Location.File,
						},
						Region: sarifRegion{
							StartLine:   violation.Location.Line,
							StartColumn: violation.Location.Column,
						},
					},
				},
			},
		}

		// Add fix if remediation is available
		if violation.Remediation != "" {
			result.Fixes = []sarifFix{
				{
					Description: sarifMessage{
						Text: violation.Remediation,
					},
				},
			}
		}

		results = append(results, result)
	}

	return &sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "PolicyGuard",
						Version:         "1.0.0",
						SemanticVersion: "1.0.0",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}