package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "suppress.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSuppression_RejectsMissingReason(t *testing.T) {
	p := writeTemp(t, `{"rules":[{"policy_id":"s3_bucket_encryption"}]}`)
	if _, err := LoadSuppressionConfig(p); err == nil {
		t.Error("expected error for rule with no reason")
	}
}

func TestLoadSuppression_RejectsBadExpiry(t *testing.T) {
	p := writeTemp(t, `{"rules":[{"policy_id":"x","reason":"r","expires":"not-a-date"}]}`)
	if _, err := LoadSuppressionConfig(p); err == nil {
		t.Error("expected error for invalid expires")
	}
}

func TestLoadSuppression_EmptyPathIsNoop(t *testing.T) {
	c, err := LoadSuppressionConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 0 {
		t.Errorf("expected no rules, got %d", len(c.Rules))
	}
}

func TestMatch_PolicyAndResourceScoping(t *testing.T) {
	c := &SuppressionConfig{Rules: []SuppressionRule{
		{PolicyID: "s3_bucket_encryption", Resource: "aws_s3_bucket.public_site", Reason: "static site, intentional"},
	}}
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)

	// Matches the exact resource.
	if _, ok := c.Match(types.PolicyViolation{PolicyID: "s3_bucket_encryption", ResourceID: "aws_s3_bucket.public_site"}, now); !ok {
		t.Error("should match the scoped resource")
	}
	// Does not match a different resource for the same policy.
	if _, ok := c.Match(types.PolicyViolation{PolicyID: "s3_bucket_encryption", ResourceID: "aws_s3_bucket.other"}, now); ok {
		t.Error("must not suppress a different resource")
	}
	// Does not match a different policy.
	if _, ok := c.Match(types.PolicyViolation{PolicyID: "s3_bucket_logging", ResourceID: "aws_s3_bucket.public_site"}, now); ok {
		t.Error("must not suppress a different policy")
	}
}

func TestMatch_ExpiredRuleDoesNotSuppress(t *testing.T) {
	c := &SuppressionConfig{Rules: []SuppressionRule{
		{PolicyID: "s3_bucket_encryption", Reason: "temporary waiver", Expires: "2026-01-01"},
	}}
	v := types.PolicyViolation{PolicyID: "s3_bucket_encryption", ResourceID: "aws_s3_bucket.b"}

	past := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	if _, ok := c.Match(v, past); !ok {
		t.Error("rule should still apply before expiry")
	}
	after := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	if _, ok := c.Match(v, after); ok {
		t.Error("expired rule must not suppress (finding should resurface)")
	}
}

func TestMatch_PolicyWideWhenNoResource(t *testing.T) {
	c := &SuppressionConfig{Rules: []SuppressionRule{
		{PolicyID: "s3_bucket_logging", Reason: "logging handled centrally"},
	}}
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	for _, rid := range []string{"aws_s3_bucket.a", "aws_s3_bucket.b"} {
		if _, ok := c.Match(types.PolicyViolation{PolicyID: "s3_bucket_logging", ResourceID: rid}, now); !ok {
			t.Errorf("policy-wide rule should suppress %s", rid)
		}
	}
}
