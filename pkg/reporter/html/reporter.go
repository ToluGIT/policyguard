// Package html renders a PolicyGuard scan report as a single self-contained
// HTML dashboard (the "terminal-mono" GUI). Everything on the page — counts,
// findings, file:line, CWE tags, evidence, remediation — comes from the real
// scan; nothing is mocked. The template, CSS, and JS are embedded so the
// reporter has no external assets and the output renders offline.
package html

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

//go:embed assets/template.html assets/body.html assets/dashboard.css assets/dashboard.js
var assets embed.FS

// Assets exposes the embedded asset filesystem so the web GUI (pkg/web) can
// reuse the same CSS/JS/templates the static reporter ships — one design source.
func Assets() embed.FS { return assets }

// evidenceContext is how many source lines to show on each side of the
// offending line in a finding's evidence block.
const evidenceContext = 3

// Reporter implements reporter.Reporter, emitting the HTML dashboard.
type Reporter struct {
	version string
	// now is injected for deterministic tests; defaults to time.Now.
	now func() time.Time
	// readFile is injected for tests; defaults to reading from disk.
	readFile func(path string) ([]byte, error)
	// evidenceRoot, when set, is joined with a finding's (display-relative)
	// file path to locate the source on disk for evidence extraction.
	evidenceRoot string
}

// New creates an HTML reporter using the default (dev) version.
func New() *Reporter { return NewWithVersion("") }

// NewWithVersion creates an HTML reporter that records the given build version
// in the report footer, mirroring the SARIF reporter so the GUI never disagrees
// with the binary.
func NewWithVersion(version string) *Reporter {
	if version == "" {
		version = "0.0.0-dev"
	}
	return &Reporter{
		version:  version,
		now:      time.Now,
		readFile: os.ReadFile,
	}
}

// Format returns the format identifier.
func (r *Reporter) Format() string { return "html" }

// Generate builds the report and summary from policy results. This mirrors the
// human reporter's convention so pass-rate and severity counts are computed the
// same way across formats.
func (r *Reporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	now := r.now()
	report := &types.Report{
		ID:         fmt.Sprintf("report-%d", now.Unix()),
		Timestamp:  now,
		Resources:  resources,
		Violations: result.Violations,
		Metadata:   result.Metadata,
	}

	violationsBySeverity := make(map[string]int)
	for _, v := range result.Violations {
		violationsBySeverity[v.Severity]++
	}

	resourcesWithViolations := countResourcesWithViolations(result.Violations)
	passRate := 100.0
	if len(resources) > 0 {
		passRate = float64(len(resources)-resourcesWithViolations) / float64(len(resources)) * 100
	}

	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             passRate,
	}
	return report, nil
}

// Write renders the full standalone dashboard page for the given report.
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	tmpl, err := template.New("template.html").Funcs(templateFuncs()).
		ParseFS(assets, "assets/template.html", "assets/body.html")
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	css, err := assets.ReadFile("assets/dashboard.css")
	if err != nil {
		return fmt.Errorf("failed to read css: %w", err)
	}
	js, err := assets.ReadFile("assets/dashboard.js")
	if err != nil {
		return fmt.Errorf("failed to read js: %w", err)
	}

	vm := r.buildViewModel(report, string(css), string(js))
	if err := tmpl.ExecuteTemplate(writer, "template.html", vm); err != nil {
		return fmt.Errorf("failed to render dashboard: %w", err)
	}
	return nil
}

// BuildViewModel exposes the report→ViewModel mapping for callers (the web GUI)
// that render the dashboard body themselves. css/js may be empty when the caller
// supplies those assets out-of-band.
func (r *Reporter) BuildViewModel(report *types.Report) ViewModel {
	return r.buildViewModel(report, "", "")
}

// RenderBody renders just the dashboard body fragment (meta strip, stat cards,
// distribution bar, findings table + detail panel, and the findings JSON island)
// for the given report. The web GUI injects this into its app shell after a
// live scan, so the live dashboard and the static report share one design.
//
// version is recorded in the meta strip (pass the build version so the GUI does
// not show the dev placeholder). sourceRoot, when non-empty, is prepended to
// each finding's (already display-relative) file path to locate the source on
// disk for evidence extraction — so the UI can show clean relative file names
// while evidence is still read from the real files. Pass "" when the report's
// file paths are already the on-disk paths.
func RenderBody(report *types.Report, version, sourceRoot string, writer io.Writer) error {
	r := NewWithVersion(version)
	r.evidenceRoot = sourceRoot
	tmpl, err := template.New("body.html").Funcs(templateFuncs()).ParseFS(assets, "assets/body.html")
	if err != nil {
		return fmt.Errorf("failed to parse body template: %w", err)
	}
	vm := r.buildViewModel(report, "", "")
	if err := tmpl.ExecuteTemplate(writer, "dashboard-body", vm); err != nil {
		return fmt.Errorf("failed to render dashboard body: %w", err)
	}
	return nil
}

// countResourcesWithViolations counts the distinct resources that have at least
// one violation (matches the human reporter's pass-rate basis).
func countResourcesWithViolations(violations []types.PolicyViolation) int {
	seen := make(map[string]struct{}, len(violations))
	for _, v := range violations {
		seen[v.ResourceID] = struct{}{}
	}
	return len(seen)
}

// readEvidence reads the source lines around a finding's location and marks the
// offending line. Returns nil when the file cannot be read — evidence is never
// fabricated.
func (r *Reporter) readEvidence(loc types.Location) []EvidenceLine {
	if loc.File == "" || loc.Line <= 0 {
		return nil
	}
	path := loc.File
	if r.evidenceRoot != "" {
		path = filepath.Join(r.evidenceRoot, loc.File)
	}
	data, err := r.readFile(path)
	if err != nil {
		return nil
	}

	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		// A scan failure (e.g. a token longer than the buffer) means we can't
		// trust the line set — omit evidence rather than show a partial/wrong one.
		return nil
	}
	// If the reported line is past the end of the file we cannot show it. This
	// can happen when line attribution is approximate (e.g. .tf.json); bail
	// rather than compute an inverted range (which would panic on make()).
	if len(lines) == 0 || loc.Line > len(lines) {
		return nil
	}

	start := loc.Line - evidenceContext
	if start < 1 {
		start = 1
	}
	end := loc.Line + evidenceContext
	if end > len(lines) {
		end = len(lines)
	}

	out := make([]EvidenceLine, 0, end-start+1)
	for n := start; n <= end; n++ {
		out = append(out, EvidenceLine{
			Number:    n,
			Text:      lines[n-1],
			Offending: n == loc.Line,
		})
	}
	return out
}

// remediationLines splits a remediation snippet into rendered diff lines. The
// suggester emits corrected HCL (additions); we render it as additions so the
// "+"/mint styling is truthful — we do not invent deletions.
func remediationLines(snippet string) []DiffLine {
	if strings.TrimSpace(snippet) == "" {
		return nil
	}
	raw := strings.Split(strings.TrimRight(snippet, "\n"), "\n")
	out := make([]DiffLine, 0, len(raw))
	for _, l := range raw {
		kind := "add"
		text := l
		switch {
		case strings.HasPrefix(l, "+"):
			kind, text = "add", strings.TrimPrefix(l, "+")
		case strings.HasPrefix(l, "-"):
			kind, text = "del", strings.TrimPrefix(l, "-")
		}
		out = append(out, DiffLine{Kind: kind, Text: text})
	}
	return out
}
