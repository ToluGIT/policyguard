package analyzer

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ToluGIT/policyguard/pkg/config"
	"github.com/ToluGIT/policyguard/pkg/parser"
	"github.com/ToluGIT/policyguard/pkg/policy"
	"github.com/ToluGIT/policyguard/pkg/remediation"
	"github.com/ToluGIT/policyguard/pkg/reporter"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// Analyzer coordinates the analysis workflow
type Analyzer struct {
	parser       parser.Parser
	engine       policy.Engine
	suggester    remediation.Suggester
	reporter     reporter.Reporter
	suppressions *config.SuppressionConfig
}

// New creates a new analyzer instance
func New(parser parser.Parser, engine policy.Engine, suggester remediation.Suggester, reporter reporter.Reporter) *Analyzer {
	return &Analyzer{
		parser:    parser,
		engine:    engine,
		suggester: suggester,
		reporter:  reporter,
	}
}

// WithSuppressions configures suppression rules. Suppressed findings are removed
// from the report's violations and summarized in metadata (count, reasons,
// per-policy ranking) so they are acknowledged and tracked, not silently lost.
func (a *Analyzer) WithSuppressions(cfg *config.SuppressionConfig) *Analyzer {
	a.suppressions = cfg
	return a
}

// AnalyzeFile analyzes a single file
func (a *Analyzer) AnalyzeFile(ctx context.Context, filePath string) (*types.Report, error) {
	resources, err := a.parser.Parse(ctx, filePath)
	if err != nil {
		return nil, err
	}
	return a.analyzeResources(ctx, resources)
}

// AnalyzePaths analyzes a set of files and/or directories together: it parses
// every path, pools the resources, and evaluates them in a single pass. Pooling
// matters because cross-resource policies (e.g. an S3 bucket whose encryption
// config lives in a sibling resource) can only see relationships when the
// related resources are evaluated together — scanning each file in isolation
// would miss a sibling defined in another changed file. This backs the CLI's
// multi-path scan and the pre-commit hook (which passes all changed files).
func (a *Analyzer) AnalyzePaths(ctx context.Context, paths []string) (*types.Report, error) {
	var resources []types.Resource
	// Dedup by resource identity so overlapping paths (the same file passed
	// twice, or a file that also lives inside a passed directory — e.g.
	// `scan . sub/`) don't double-count findings. Identity is the resource ID
	// plus its source location, which uniquely pins a parsed resource.
	seen := make(map[string]bool)
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("failed to access %s: %w", p, err)
		}
		var parsed []types.Resource
		if info.IsDir() {
			parsed, err = a.parser.ParseDirectory(ctx, p)
		} else {
			parsed, err = a.parser.Parse(ctx, p)
		}
		if err != nil {
			return nil, err
		}
		for _, r := range parsed {
			key := fmt.Sprintf("%s\x00%s:%d:%d", r.ID, r.Location.File, r.Location.Line, r.Location.Column)
			if seen[key] {
				continue
			}
			seen[key] = true
			resources = append(resources, r)
		}
	}
	return a.analyzeResources(ctx, resources)
}

// analyzeResources runs the shared evaluate → sort → suppress → suggest →
// report pipeline over an already-parsed resource set.
func (a *Analyzer) analyzeResources(ctx context.Context, resources []types.Resource) (*types.Report, error) {
	result, err := a.engine.Evaluate(ctx, resources)
	if err != nil {
		return nil, err
	}
	sortViolations(result.Violations)
	a.applySuppressions(result)
	a.applySuggestions(ctx, result.Violations, resources)

	report, err := a.reporter.Generate(ctx, result, resources)
	if err != nil {
		return nil, err
	}
	return report, nil
}

// applySuggestions attaches a corrected-HCL snippet to each violation when a
// remediation suggester is configured and a template exists. It is best-effort:
// any error or missing template simply leaves the snippet empty, so reporting is
// never blocked by remediation. No-op when no suggester was provided.
func (a *Analyzer) applySuggestions(ctx context.Context, violations []types.PolicyViolation, resources []types.Resource) {
	if a.suggester == nil {
		return
	}
	resourceMap := make(map[string]types.Resource, len(resources))
	for _, r := range resources {
		resourceMap[r.ID] = r
	}
	for i := range violations {
		resource, ok := resourceMap[violations[i].ResourceID]
		if !ok {
			continue
		}
		suggestion, err := a.suggester.Suggest(ctx, violations[i], resource)
		if err != nil || suggestion == nil || suggestion.CodeFix == nil {
			continue
		}
		violations[i].RemediationSnippet = suggestion.CodeFix.NewContent
	}
}

// applySuppressions removes findings matched by a suppression rule from result,
// and records what was suppressed in result.Metadata: the total count, a
// per-policy ranking (so precision work can target the policies generating the
// most suppressed findings), and the reason for each. No-op when no suppression
// config is set. Returns the (possibly trimmed) violation slice.
func (a *Analyzer) applySuppressions(result *types.PolicyResult) {
	if a.suppressions == nil || len(a.suppressions.Rules) == 0 {
		return
	}
	now := time.Now().UTC()

	kept := result.Violations[:0]
	suppressedByPolicy := map[string]int{}
	type suppressedEntry struct {
		ResourceID string `json:"resource_id"`
		PolicyID   string `json:"policy_id"`
		Reason     string `json:"reason"`
	}
	var suppressed []suppressedEntry

	for _, v := range result.Violations {
		if rule, ok := a.suppressions.Match(v, now); ok {
			suppressedByPolicy[v.PolicyID]++
			suppressed = append(suppressed, suppressedEntry{v.ResourceID, v.PolicyID, rule.Reason})
			continue
		}
		kept = append(kept, v)
	}
	result.Violations = kept
	result.Passed = len(kept) == 0

	if len(suppressed) == 0 {
		return
	}
	if result.Metadata == nil {
		result.Metadata = map[string]interface{}{}
	}
	result.Metadata["suppressed_count"] = len(suppressed)
	result.Metadata["suppressed_by_policy"] = suppressedByPolicy
	result.Metadata["suppressed"] = suppressed
}

// sortViolations orders violations canonically so reports are deterministic
// across runs regardless of filesystem-dependent file/resource discovery order
// (e.g. directory globbing). Without this, re-running the same scan could emit
// the same findings in a different order, producing noisy diffs and tripping
// baseline comparisons in CI and audit workflows. The key is the stable logical
// identity of a finding: location, then resource, then policy, then finding ID.
func sortViolations(violations []types.PolicyViolation) {
	sort.SliceStable(violations, func(i, j int) bool {
		a, b := violations[i], violations[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.ResourceID != b.ResourceID {
			return a.ResourceID < b.ResourceID
		}
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		return a.ID < b.ID
	})
}

// AnalyzeDirectory analyzes all files in a directory
func (a *Analyzer) AnalyzeDirectory(ctx context.Context, dirPath string) (*types.Report, error) {
	resources, err := a.parser.ParseDirectory(ctx, dirPath)
	if err != nil {
		return nil, err
	}
	return a.analyzeResources(ctx, resources)
}
