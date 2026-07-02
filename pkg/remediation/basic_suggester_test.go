package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// TestSuggest_CorePoliciesResolveCodeFix guards the bug where templates were
// keyed by a hyphenated form ("s3-bucket-encryption") that never matched the
// real underscore policy_ids, so every lookup silently fell through to generic.
// Each core policy must resolve a specific (non-generic) suggestion with an HCL
// code fix.
func TestSuggest_CorePoliciesResolveCodeFix(t *testing.T) {
	s := NewBasicSuggester()
	ctx := context.Background()

	corePolicies := []string{
		"s3_bucket_encryption",
		"s3_bucket_public_access",
		"s3_bucket_logging",
		"ec2_instance_public_ip",
		"ec2_instance_encryption",
		"ebs_volume_encryption",
		"ec2_instance_imdsv2",
		"security_group_ssh_open",
		"security_group_unrestricted",
		"rds_encryption_required",
		"rds_no_public_access",
	}

	for _, pid := range corePolicies {
		t.Run(pid, func(t *testing.T) {
			v := types.PolicyViolation{ID: "v-" + pid, PolicyID: pid, ResourceID: "aws_x.test"}
			r := types.Resource{ID: "aws_x.test", Type: "aws_x", Name: "test"}

			sug, err := s.Suggest(ctx, v, r)
			if err != nil {
				t.Fatalf("Suggest: %v", err)
			}
			if sug.Type == "generic" {
				t.Errorf("policy %q fell through to a generic suggestion (template key mismatch)", pid)
			}
			if sug.CodeFix == nil || sug.CodeFix.NewContent == "" {
				t.Errorf("policy %q produced no HCL code fix", pid)
			}
		})
	}
}

// TestSuggest_SnippetsHaveBalancedBraces guards against shipping a malformed HCL
// snippet: any snippet that opens a brace must close all of them, or a user who
// copies the "Suggested HCL" gets a Terraform syntax error.
func TestSuggest_SnippetsHaveBalancedBraces(t *testing.T) {
	s := NewBasicSuggester()
	ctx := context.Background()
	r := types.Resource{ID: "aws_s3_bucket.b", Type: "aws_s3_bucket", Name: "b"}

	for pid := range s.suggestions {
		t.Run(pid, func(t *testing.T) {
			sug, err := s.Suggest(ctx, types.PolicyViolation{ID: "v", PolicyID: pid, ResourceID: r.ID}, r)
			if err != nil || sug.CodeFix == nil {
				return
			}
			c := sug.CodeFix.NewContent
			if strings.Count(c, "{") != strings.Count(c, "}") {
				t.Errorf("policy %q snippet has unbalanced braces (%d open, %d close):\n%s",
					pid, strings.Count(c, "{"), strings.Count(c, "}"), c)
			}
		})
	}
}

// TestSuggest_UnknownPolicyIsGeneric confirms an unmapped policy still returns a
// usable generic suggestion rather than erroring.
func TestSuggest_UnknownPolicyIsGeneric(t *testing.T) {
	s := NewBasicSuggester()
	v := types.PolicyViolation{ID: "v1", PolicyID: "totally_unknown", ResourceID: "aws_x.t"}
	r := types.Resource{ID: "aws_x.t", Type: "aws_x", Name: "t"}

	sug, err := s.Suggest(context.Background(), v, r)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if sug.Type != "generic" {
		t.Errorf("unknown policy should yield a generic suggestion, got %q", sug.Type)
	}
}

// TestSuggest_S3EncryptionFixIsValidHCLShape sanity-checks the generated snippet
// references the right block.
func TestSuggest_S3EncryptionFixIsValidHCLShape(t *testing.T) {
	s := NewBasicSuggester()
	v := types.PolicyViolation{ID: "v1", PolicyID: "s3_bucket_encryption", ResourceID: "aws_s3_bucket.b"}
	r := types.Resource{ID: "aws_s3_bucket.b", Type: "aws_s3_bucket", Name: "b"}

	sug, err := s.Suggest(context.Background(), v, r)
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if !strings.Contains(sug.CodeFix.NewContent, "server_side_encryption_configuration") {
		t.Errorf("S3 encryption fix should mention server_side_encryption_configuration, got:\n%s", sug.CodeFix.NewContent)
	}
}
