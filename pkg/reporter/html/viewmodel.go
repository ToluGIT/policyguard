package html

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/ToluGIT/policyguard/pkg/compliance"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// ViewModel is the data handed to the dashboard template. Every field is
// derived from the real report — there is no placeholder data.
type ViewModel struct {
	Version     string
	GeneratedAt string
	CSS         template.CSS
	JS          template.JS

	// Scan-meta strip (only fields the report actually carries).
	TotalResources  int
	TotalViolations int
	TotalChecks     int // resources scanned == checks attempted (best available)
	PassRate        string
	PassRateValue   float64
	SuppressedCount int

	// Severity stat cards, in display order.
	Stats []SeverityStat

	// Stacked distribution segments (FAIL severities + PASS), display order.
	Distribution []DistSegment

	// Findings table / detail data.
	Findings []Finding

	// FindingsJSON is the embedded data island the client JS reads for
	// filtering/search/selection. Built from Findings; safely escaped.
	FindingsJSON template.JS
}

// SeverityStat is one of the five top stat cards.
type SeverityStat struct {
	Key        string // critical|high|medium|low|pass
	Label      string // CRITICAL ...
	Count      int
	Descriptor string // "must fix" ...
	IsPass     bool
}

// DistSegment is one segment of the stacked distribution bar.
type DistSegment struct {
	Key     string
	Count   int
	Percent float64
	IsPass  bool
}

// Finding is a single row + its detail-panel content.
type Finding struct {
	Index        int
	ResourceID   string
	ResourceType string // human label e.g. "S3 Bucket"
	PolicyID     string
	Title        string // Message
	Severity     string // lower-case key
	SeverityUp   string // upper-case label
	File         string
	Line         int
	Provider     string
	Details      string
	Remediation  string
	CWE          []CWETag
	CIS          []string // only populated when the mapping has them
	NIST         []string // only populated when the mapping has them
	Evidence     []EvidenceLine
	Diff         []DiffLine
}

// CWETag is a CWE id plus its human title.
type CWETag struct {
	ID    string
	Title string
}

// EvidenceLine is one source line in the evidence block.
type EvidenceLine struct {
	Number    int
	Text      string
	Offending bool
}

// DiffLine is one line of the remediation diff.
type DiffLine struct {
	Kind string // add|del|ctx
	Text string
}

// severityOrder is the canonical display order for the failing severities, used
// for both the stat cards and the distribution bar. "info" is intentionally NOT
// a separate bucket here: it is folded into "low" everywhere (see buildViewModel)
// so the cards and the distribution bar represent the same data identically.
var severityOrder = []string{
	types.SeverityCritical,
	types.SeverityHigh,
	types.SeverityMedium,
	types.SeverityLow,
}

var severityDescriptor = map[string]string{
	types.SeverityCritical: "must fix",
	types.SeverityHigh:     "review",
	types.SeverityMedium:   "advisory",
	types.SeverityLow:      "informational",
	types.SeverityInfo:     "informational",
}

func (r *Reporter) buildViewModel(report *types.Report, css, js string) ViewModel {
	vm := ViewModel{
		Version:         r.version,
		GeneratedAt:     report.Timestamp.Format("2006-01-02 15:04:05 MST"),
		CSS:             template.CSS(css),
		JS:              template.JS(js),
		TotalResources:  report.Summary.TotalResources,
		TotalViolations: report.Summary.TotalViolations,
		TotalChecks:     report.Summary.TotalResources,
		PassRate:        fmt.Sprintf("%.1f", report.Summary.PassRate),
		PassRateValue:   report.Summary.PassRate,
	}

	if n, ok := report.Metadata["suppressed_count"].(int); ok {
		vm.SuppressedCount = n
	}

	bySev := report.Summary.ViolationsBySeverity
	passCount := report.Summary.TotalResources - countResourcesWithViolations(report.Violations)
	if passCount < 0 {
		passCount = 0
	}

	// Stat cards: four failing buckets (critical/high/medium/low — info folds
	// into low's "informational" descriptor only if present) + PASS.
	for _, sev := range []string{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow} {
		count := bySev[sev]
		if sev == types.SeverityLow {
			count += bySev[types.SeverityInfo] // fold info into the low/informational card
		}
		vm.Stats = append(vm.Stats, SeverityStat{
			Key:        sev,
			Label:      strings.ToUpper(sev),
			Count:      count,
			Descriptor: severityDescriptor[sev],
		})
	}
	vm.Stats = append(vm.Stats, SeverityStat{
		Key: "pass", Label: "PASS", Count: passCount, Descriptor: "checks passed", IsPass: true,
	})

	// Distribution bar: severity counts + pass, percent of total.
	total := report.Summary.TotalViolations + passCount
	if total == 0 {
		total = 1
	}
	for _, sev := range severityOrder {
		c := bySev[sev]
		if sev == types.SeverityLow {
			c += bySev[types.SeverityInfo] // fold info into low, matching the stat cards
		}
		if c == 0 {
			continue
		}
		vm.Distribution = append(vm.Distribution, DistSegment{
			Key: sev, Count: c, Percent: float64(c) / float64(total) * 100,
		})
	}
	if passCount > 0 {
		vm.Distribution = append(vm.Distribution, DistSegment{
			Key: "pass", Count: passCount, Percent: float64(passCount) / float64(total) * 100, IsPass: true,
		})
	}

	// Findings (already sorted deterministically by the analyzer; keep that order).
	for i, v := range report.Violations {
		f := Finding{
			Index:        i,
			ResourceID:   v.ResourceID,
			ResourceType: resourceTypeLabel(v.ResourceID),
			PolicyID:     v.PolicyID,
			Title:        v.Message,
			Severity:     strings.ToLower(v.Severity),
			SeverityUp:   strings.ToUpper(v.Severity),
			File:         v.Location.File,
			Line:         v.Location.Line,
			Provider:     providerFromResourceID(v.ResourceID),
			Details:      v.Details,
			Remediation:  v.Remediation,
			Evidence:     r.readEvidence(v.Location),
			Diff:         remediationLines(v.RemediationSnippet),
		}
		if m, ok := compliance.For(v.PolicyID); ok {
			for _, c := range m.CWE {
				f.CWE = append(f.CWE, CWETag{ID: c, Title: compliance.CWETitle(c)})
			}
			f.CIS = m.CIS   // only non-empty when the mapping genuinely has them
			f.NIST = m.NIST // ditto — never guessed
		}
		vm.Findings = append(vm.Findings, f)
	}

	vm.FindingsJSON = template.JS(findingsToJSON(vm.Findings))
	return vm
}

// resourceTypeLabel turns "aws_s3_bucket.assets" into a friendly "S3 Bucket"
// label where we recognize the type, else a cleaned-up type token. Purely
// cosmetic; derived from the real resource id, not invented.
func resourceTypeLabel(resourceID string) string {
	t := resourceID
	if i := strings.Index(t, "."); i > 0 {
		t = t[:i]
	}
	if label, ok := knownTypeLabels[t]; ok {
		return label
	}
	// Fallback: strip provider prefix, title-case the remainder.
	parts := strings.Split(t, "_")
	if len(parts) > 1 {
		parts = parts[1:]
	}
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

var knownTypeLabels = map[string]string{
	"aws_s3_bucket":                  "S3 Bucket",
	"aws_security_group":             "Security Group",
	"aws_iam_policy":                 "IAM Policy",
	"aws_iam_role":                   "IAM Role",
	"aws_instance":                   "EC2 Instance",
	"aws_ebs_volume":                 "EBS Volume",
	"aws_sqs_queue":                  "SQS Queue",
	"aws_sns_topic":                  "SNS Topic",
	"aws_dynamodb_table":             "DynamoDB Table",
	"aws_kms_key":                    "KMS Key",
	"aws_lambda_function":            "Lambda Function",
	"aws_db_instance":                "RDS Instance",
	"aws_rds_cluster":                "RDS Cluster",
	"aws_elb":                        "Classic ELB",
	"aws_lb":                         "Load Balancer",
	"aws_cloudtrail":                 "CloudTrail",
	"aws_ecr_repository":             "ECR Repository",
	"azurerm_storage_account":        "Storage Account",
	"azurerm_network_security_group": "Network Security Group",
	"azurerm_mssql_server":           "SQL Server",
}

// providerFromResourceID derives the cloud provider token from a resource id
// prefix (aws_*, azurerm_*, google_*). Returns "" when unknown.
func providerFromResourceID(resourceID string) string {
	switch {
	case strings.HasPrefix(resourceID, "aws_"):
		return "aws"
	case strings.HasPrefix(resourceID, "azurerm_"), strings.HasPrefix(resourceID, "azure_"):
		return "azure"
	case strings.HasPrefix(resourceID, "google_"):
		return "gcp"
	default:
		return ""
	}
}
