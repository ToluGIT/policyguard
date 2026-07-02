package compliance

import (
	"bytes"
	"context"
	"encoding/csv"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

func render(t *testing.T) [][]string {
	t.Helper()
	report := &types.Report{
		Violations: []types.PolicyViolation{
			{
				ResourceID:  "aws_s3_bucket.b1",
				PolicyID:    "s3_bucket_encryption", // mapped -> CWE-311
				Severity:    "high",
				Message:     "bucket not encrypted",
				Remediation: "enable encryption",
			},
			{
				ResourceID:  "aws_db_instance.db1",
				PolicyID:    "rds_iam_authentication", // unmapped
				Severity:    "medium",
				Message:     "no iam auth",
				Remediation: "enable iam auth",
			},
		},
	}

	var buf bytes.Buffer
	if err := New().Write(context.Background(), report, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	return rows
}

func TestCompliance_HeaderAndShape(t *testing.T) {
	rows := render(t)
	if len(rows) != 3 { // header + 2 findings
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	want := []string{"resource", "policy_id", "severity", "cwe", "cwe_title", "message", "remediation"}
	for i, h := range want {
		if rows[0][i] != h {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], h)
		}
	}
}

func TestCompliance_MappedPolicyHasCWE(t *testing.T) {
	rows := render(t)
	// row 1 is the s3_bucket_encryption finding
	row := rows[1]
	if row[1] != "s3_bucket_encryption" {
		t.Fatalf("unexpected row order: %v", row)
	}
	if row[3] != "CWE-311" {
		t.Errorf("cwe column = %q, want CWE-311", row[3])
	}
	if row[4] == "" {
		t.Error("cwe_title should be populated for a mapped policy")
	}
}

func TestCompliance_UnmappedPolicyMarkedHonestly(t *testing.T) {
	rows := render(t)
	row := rows[2] // rds_iam_authentication
	if row[1] != "rds_iam_authentication" {
		t.Fatalf("unexpected row order: %v", row)
	}
	if row[3] != "unmapped" {
		t.Errorf("unmapped policy cwe column = %q, want \"unmapped\"", row[3])
	}
	if row[4] != "" {
		t.Errorf("unmapped policy should have empty cwe_title, got %q", row[4])
	}
}

func TestCompliance_FormatName(t *testing.T) {
	if got := New().Format(); got != "compliance" {
		t.Errorf("Format() = %q, want compliance", got)
	}
}

// TestCompliance_EscapesFreeTextAndJoinsMultiCWE guards two things at once:
// free-text fields (message/remediation) that contain commas, quotes, and
// newlines must not break the CSV columns, and a policy mapped to multiple CWEs
// must keep the cwe and cwe_title columns parallel.
func TestCompliance_EscapesFreeTextAndJoinsMultiCWE(t *testing.T) {
	report := &types.Report{
		Violations: []types.PolicyViolation{
			{
				ResourceID:  "aws_s3_bucket.b1",
				PolicyID:    "s3_bucket_public_access", // mapped to CWE-200;CWE-284
				Severity:    "critical",
				Message:     `Bucket "b1", public, allows read,write`,
				Remediation: "line one\nline two, with comma",
			},
		},
	}

	var buf bytes.Buffer
	if err := New().Write(context.Background(), report, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("CSV did not round-trip with special characters: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want header + 1 row, got %d rows", len(rows))
	}
	row := rows[1]
	if len(row) != 7 {
		t.Fatalf("special characters split the row into %d cols: %v", len(row), row)
	}
	if row[3] != "CWE-200;CWE-284" {
		t.Errorf("multi-CWE cwe column = %q, want CWE-200;CWE-284", row[3])
	}
	// cwe_title must list both titles in the same order as the CWEs.
	wantTitle := "Exposure of Sensitive Information to an Unauthorized Actor;Improper Access Control"
	if row[4] != wantTitle {
		t.Errorf("multi-CWE title column = %q, want %q", row[4], wantTitle)
	}
	if row[5] != `Bucket "b1", public, allows read,write` {
		t.Errorf("message field was mangled: %q", row[5])
	}
}
