package sarif

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ToluGIT/policyguard/pkg/compliance"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// defaultVersion is used when the reporter is constructed without an explicit
// build version. It is intentionally a placeholder, not a real release number,
// so a stale hardcoded version can never masquerade as the shipping build.
const defaultVersion = "0.0.0-dev"

// Reporter implements the SARIF format reporter
type Reporter struct {
	version string
}

// New creates a new SARIF reporter using the default (dev) version. Prefer
// NewWithVersion so the SARIF tool version matches the actual build.
func New() *Reporter {
	return &Reporter{version: defaultVersion}
}

// NewWithVersion creates a SARIF reporter that reports the given build version
// as the tool's version/semanticVersion. The CLI threads its real version here
// so SARIF output never disagrees with the binary.
func NewWithVersion(version string) *Reporter {
	if version == "" {
		version = defaultVersion
	}
	return &Reporter{version: version}
}

// Generate creates a report from policy results
func (r *Reporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	report := &types.Report{
		ID:         fmt.Sprintf("report-%d", time.Now().Unix()),
		Timestamp:  time.Now(),
		Resources:  resources,
		Violations: result.Violations,
		Metadata:   result.Metadata,
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

// Write writes the report to the given writer in SARIF format
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	sarifReport := r.toSARIF(report)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifReport)
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
	return "sarif"
}

// SARIF structures
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
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
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifText              `json:"shortDescription"`
	FullDescription  sarifText              `json:"fullDescription"`
	Help             sarifText              `json:"help"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	DefaultConfig    sarifRuleConfig        `json:"defaultConfiguration"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Fixes               []sarifFix        `json:"fixes,omitempty"`
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
	Description sarifMessage  `json:"description"`
	Changes     []sarifChange `json:"artifactChanges"`
}

type sarifChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion   sarifRegion  `json:"deletedRegion"`
	InsertedContent sarifContent `json:"insertedContent"`
}

type sarifContent struct {
	Text string `json:"text"`
}

func (r *Reporter) toSARIF(report *types.Report) *sarifReport {
	// Collect unique rules in first-seen order so both the rules array and the
	// ruleIndex references are deterministic (map iteration order is not).
	rules := make([]sarifRule, 0)
	ruleIndex := make(map[string]int)
	for _, violation := range report.Violations {
		if _, exists := ruleIndex[violation.PolicyID]; exists {
			continue
		}
		ruleIndex[violation.PolicyID] = len(rules)

		properties := map[string]interface{}{
			"severity": violation.Severity,
		}
		// tags carry the GitHub code-scanning convention "external/cwe/cwe-NNN"
		// alongside the generic security tags, so findings group by weakness.
		tags := []string{"security", "infrastructure-as-code", "terraform"}
		if cwes := compliance.CWEsFor(violation.PolicyID); len(cwes) > 0 {
			properties["cwe"] = cwes
			for _, cwe := range cwes {
				tags = append(tags, "external/cwe/"+strings.ToLower(cwe))
			}
		}
		properties["tags"] = tags

		rule := sarifRule{
			ID:   violation.PolicyID,
			Name: violation.PolicyID,
			ShortDescription: sarifText{
				Text: getPolicyTitle(violation.PolicyID),
			},
			FullDescription: sarifText{
				Text: violation.Details,
			},
			Help: sarifText{
				Text: violation.Remediation,
			},
			HelpURI:       helpURIFor(violation.PolicyID),
			DefaultConfig: sarifRuleConfig{Level: severityToSARIFLevel(violation.Severity)},
			Properties:    properties,
		}
		rules = append(rules, rule)
	}

	// Build results
	results := make([]sarifResult, 0)
	// occurrence counts how many findings already share a given fingerprint base,
	// so multiple distinct findings of the same policy on the same resource (e.g.
	// a security group that is both SSH-open and all-traffic-open) get distinct,
	// stable fingerprints instead of colliding and being deduped into one.
	occurrence := make(map[string]int)
	for _, violation := range report.Violations {
		base := fingerprintBase(violation)
		n := occurrence[base]
		occurrence[base]++

		result := sarifResult{
			RuleID:    violation.PolicyID,
			RuleIndex: ruleIndex[violation.PolicyID],
			Level:     severityToSARIFLevel(violation.Severity),
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
			// partialFingerprints give a stable identity across runs so code
			// scanning can dedupe and track a finding even when line numbers
			// shift. We key on the logical identity of the finding (policy +
			// resource + finding-id + file), not the line, so a finding that
			// merely moves keeps its identity, while two distinct findings never
			// collide.
			PartialFingerprints: map[string]string{
				"policyguardFindingV1": hashFingerprint(base, n),
			},
		}

		// Note: We don't add fixes because SARIF requires artifactChanges with minItems: 1
		// Since we only have remediation text without actual code changes, we skip the fixes field
		// The remediation text is already included in the help text of the rule

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
						Version:         r.version,
						SemanticVersion: r.version,
						InformationURI:  "https://github.com/ToluGIT/policyguard",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}
}

// fingerprintBase is the line-independent logical identity of a finding. It
// includes the violation's own ID (which distinguishes the multiple deny rules a
// single policy can have, e.g. SSH-open vs all-traffic-open) in addition to the
// policy, resource, and file. Excluding the line means a finding that merely
// moves within a file keeps its identity across runs.
func fingerprintBase(v types.PolicyViolation) string {
	return strings.Join([]string{v.PolicyID, v.ResourceID, v.ID, v.Location.File}, "\x00")
}

// hashFingerprint hashes the base plus an occurrence index. The index is a
// tiebreaker for the rare case where two findings share an identical base
// (same policy, resource, ID, and file); it guarantees distinct findings get
// distinct fingerprints instead of colliding and being deduped.
func hashFingerprint(base string, occurrence int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", base, occurrence)))
	return hex.EncodeToString(h[:])
}

// helpURIFor links a rule to its documentation. We point at the policy source in
// the repo, which is real and verifiable, rather than inventing a docs URL.
func helpURIFor(policyID string) string {
	return "https://github.com/ToluGIT/policyguard/tree/main/policies"
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

// getPolicyTitle returns a generic title for a given policy ID
func getPolicyTitle(policyID string) string {
	// Smart title generation from policy ID
	// This handles most cases automatically without manual mapping

	// Replace common abbreviations and make them uppercase
	replacements := map[string]string{
		"iam":    "IAM",
		"ec2":    "EC2",
		"s3":     "S3",
		"rds":    "RDS",
		"vpc":    "VPC",
		"acl":    "ACL",
		"mfa":    "MFA",
		"ssh":    "SSH",
		"ebs":    "EBS",
		"az":     "AZ",
		"dlq":    "DLQ",
		"cors":   "CORS",
		"imdsv2": "IMDSv2",
		"kms":    "KMS",
		"dns":    "DNS",
		"cidr":   "CIDR",
	}

	// Split policy ID by underscore or hyphen
	policyID = strings.ReplaceAll(policyID, "-", "_")
	words := strings.Split(policyID, "_")

	// Process each word
	for i, word := range words {
		// Check if word has a replacement
		if replacement, exists := replacements[strings.ToLower(word)]; exists {
			words[i] = replacement
		} else if len(word) > 0 {
			// Otherwise, capitalize first letter
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}

	// Special handling for common patterns
	title := strings.Join(words, " ")

	// Clean up common patterns
	title = strings.ReplaceAll(title, " No ", " ")
	title = strings.ReplaceAll(title, "Security Group", "Security Group")

	// Add clarifying text for some patterns
	if strings.Contains(title, "No Wildcard") {
		title = strings.ReplaceAll(title, "No Wildcard", "Wildcard")
	}

	return title
}
