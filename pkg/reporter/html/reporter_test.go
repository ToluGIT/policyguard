package html

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

func fixedReporter(t *testing.T) *Reporter {
	t.Helper()
	r := NewWithVersion("9.9.9")
	r.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	return r
}

func render(t *testing.T, r *Reporter, result *types.PolicyResult, resources []types.Resource) string {
	t.Helper()
	ctx := context.Background()
	report, err := r.Generate(ctx, result, resources)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var buf bytes.Buffer
	if err := r.Write(ctx, report, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.String()
}

func TestFormat(t *testing.T) {
	if got := New().Format(); got != "html" {
		t.Fatalf("Format()=%q, want html", got)
	}
}

// TestRendersRealFindings verifies the dashboard renders the actual findings,
// counts, and version — nothing placeholder.
func TestRendersRealFindings(t *testing.T) {
	r := fixedReporter(t)
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{
				ID: "v1", ResourceID: "aws_s3_bucket.assets", PolicyID: "s3_bucket_public_access",
				Severity: "critical", Message: "S3 bucket grants public-read access",
				Details: "Anonymous read exposure.", Location: types.Location{File: "main.tf", Line: 3},
			},
		},
		Metadata: map[string]interface{}{},
	}
	resources := []types.Resource{
		{ID: "aws_s3_bucket.assets", Type: "aws_s3_bucket"},
		{ID: "aws_s3_bucket.clean", Type: "aws_s3_bucket"},
	}
	out := render(t, r, result, resources)

	for _, want := range []string{
		"S3 bucket grants public-read access",
		"aws_s3_bucket.assets",
		"s3_bucket_public_access",
		"S3 Bucket",      // friendly type label
		"CWE-200",        // real CWE mapping for this policy
		"v9.9.9",         // threaded version
		`data-count="1"`, // critical stat card count
		`id="findings-data"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

// TestNoUnmappedComplianceTags asserts the honest-data contract: a policy with
// no CIS/NIST mapping must not render guessed CIS/NIST tags.
func TestNoUnmappedComplianceTags(t *testing.T) {
	r := fixedReporter(t)
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{ID: "v1", ResourceID: "aws_s3_bucket.x", PolicyID: "s3_bucket_public_access",
				Severity: "critical", Message: "m", Location: types.Location{File: "f.tf", Line: 1}},
		},
		Metadata: map[string]interface{}{},
	}
	out := render(t, r, result, []types.Resource{{ID: "aws_s3_bucket.x"}})
	if strings.Contains(out, "CIS ") || strings.Contains(out, "NIST ") {
		t.Error("rendered a CIS/NIST tag for a policy that has no such mapping")
	}
	if !strings.Contains(out, "CWE-") {
		t.Error("expected the real CWE tag to be present")
	}
}

// TestEvidenceExtraction reads real source lines around the finding and marks
// the offending line; an unreadable file yields no evidence (never fabricated).
func TestEvidenceExtraction(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	src := "line1\nline2\nresource \"aws_s3_bucket\" \"x\" {\n  acl = \"public-read\"\n}\nline6\n"
	if err := os.WriteFile(tf, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	r := fixedReporter(t)
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{ID: "v1", ResourceID: "aws_s3_bucket.x", PolicyID: "s3_bucket_public_access",
				Severity: "critical", Message: "m", Location: types.Location{File: tf, Line: 4}},
		},
		Metadata: map[string]interface{}{},
	}
	out := render(t, r, result, []types.Resource{{ID: "aws_s3_bucket.x"}})
	if !strings.Contains(out, `acl = &#34;public-read&#34;`) && !strings.Contains(out, "acl =") {
		t.Error("expected the offending source line in the evidence block")
	}
	if !strings.Contains(out, "offending") {
		t.Error("expected the offending line to be marked")
	}

	// Unreadable file → no evidence block fabricated.
	result.Violations[0].Location.File = filepath.Join(dir, "does-not-exist.tf")
	out2 := render(t, r, result, []types.Resource{{ID: "aws_s3_bucket.x"}})
	if strings.Contains(out2, "class=\"code-line") {
		t.Error("evidence block rendered for an unreadable file (should be omitted)")
	}
}

// TestEvidenceLineBeyondEOF guards against a panic when a finding's line number
// is past the end of the file (possible with approximate line attribution): the
// evidence range must not invert and blow up make().
func TestEvidenceLineBeyondEOF(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "short.tf")
	if err := os.WriteFile(tf, []byte("only\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := fixedReporter(t)
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{ID: "v1", ResourceID: "aws_s3_bucket.x", PolicyID: "p", Severity: "high",
				Message: "m", Location: types.Location{File: tf, Line: 999}},
		},
		Metadata: map[string]interface{}{},
	}
	// Must not panic; evidence simply omitted.
	out := render(t, r, result, []types.Resource{{ID: "aws_s3_bucket.x"}})
	if strings.Contains(out, `class="code-line`) {
		t.Error("evidence rendered for an out-of-range line (should be omitted)")
	}
}

// TestInfoFoldedConsistently asserts that "info" findings are folded into the
// "low" bucket in BOTH the stat cards and the distribution bar — never shown as
// a separate severity in one place but not the other.
func TestInfoFoldedConsistently(t *testing.T) {
	r := fixedReporter(t)
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{ID: "a", ResourceID: "aws_s3_bucket.x", PolicyID: "p", Severity: "low", Message: "m", Location: types.Location{File: "f", Line: 1}},
			{ID: "b", ResourceID: "aws_s3_bucket.y", PolicyID: "q", Severity: "info", Message: "m", Location: types.Location{File: "f", Line: 1}},
		},
		Metadata: map[string]interface{}{},
	}
	resources := []types.Resource{{ID: "aws_s3_bucket.x"}, {ID: "aws_s3_bucket.y"}}
	report, err := r.Generate(context.Background(), result, resources)
	if err != nil {
		t.Fatal(err)
	}
	vm := r.buildViewModel(report, "", "")

	// LOW stat card should show 2 (low + info); no separate "info" card exists.
	var lowCard *SeverityStat
	for i := range vm.Stats {
		if vm.Stats[i].Key == "info" {
			t.Error("found a separate info stat card; info must fold into low")
		}
		if vm.Stats[i].Key == "low" {
			lowCard = &vm.Stats[i]
		}
	}
	if lowCard == nil || lowCard.Count != 2 {
		t.Errorf("low stat card count = %v, want 2 (low+info folded)", lowCard)
	}
	// Distribution must not carry a separate info segment.
	for _, d := range vm.Distribution {
		if d.Key == "info" {
			t.Error("distribution has a separate info segment; info must fold into low")
		}
	}
}

// TestHTMLInjectionEscaped ensures a malicious resource name / message from a
// crafted .tf cannot break out of the HTML context.
func TestHTMLInjectionEscaped(t *testing.T) {
	r := fixedReporter(t)
	evil := `</script><img src=x onerror=alert(1)>`
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{ID: "v1", ResourceID: evil, PolicyID: "p", Severity: "high",
				Message: evil, Details: evil, Location: types.Location{File: "f.tf", Line: 1}},
		},
		Metadata: map[string]interface{}{},
	}
	out := render(t, r, result, []types.Resource{{ID: evil}})
	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Error("unescaped attacker markup present in output")
	}
	if strings.Contains(out, "</script><img") {
		t.Error("attacker closed the script/HTML context")
	}
}

// TestPassRateAndCounts checks summary math feeds the cards/meta correctly.
func TestPassRateAndCounts(t *testing.T) {
	r := fixedReporter(t)
	result := &types.PolicyResult{
		Violations: []types.PolicyViolation{
			{ID: "a", ResourceID: "aws_s3_bucket.x", PolicyID: "p", Severity: "critical", Message: "m", Location: types.Location{File: "f", Line: 1}},
			{ID: "b", ResourceID: "aws_s3_bucket.x", PolicyID: "q", Severity: "high", Message: "m", Location: types.Location{File: "f", Line: 1}},
		},
		Metadata: map[string]interface{}{},
	}
	// 4 resources, 1 has violations → 75% pass, 3 pass.
	resources := []types.Resource{
		{ID: "aws_s3_bucket.x"}, {ID: "aws_s3_bucket.a"},
		{ID: "aws_s3_bucket.b"}, {ID: "aws_s3_bucket.c"},
	}
	out := render(t, r, result, resources)
	if !strings.Contains(out, `data-value="75"`) {
		t.Error("expected 75% pass rate value")
	}
	if !strings.Contains(out, `checks passed`) {
		t.Error("expected PASS card")
	}
}

// TestEmptyReport renders a clean scan without errors.
func TestEmptyReport(t *testing.T) {
	r := fixedReporter(t)
	out := render(t, r, &types.PolicyResult{Metadata: map[string]interface{}{}}, []types.Resource{{ID: "aws_s3_bucket.ok"}})
	if !strings.Contains(out, "No violations found") {
		t.Error("expected clean-scan message")
	}
}
