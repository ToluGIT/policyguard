package opa

import (
	"context"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// loadS3Engine returns an engine with the real S3 policies loaded.
func loadS3Engine(t *testing.T) *Engine {
	t.Helper()
	e := New()
	ctx := context.Background()
	for _, p := range []string{
		"../../../policies/aws/s3_bucket_encryption.rego",
		"../../../policies/aws/s3_bucket_public_access.rego",
	} {
		if err := e.LoadPolicy(ctx, p); err != nil {
			t.Fatalf("load %s: %v", p, err)
		}
	}
	return e
}

func firedEncryption(violations []types.PolicyViolation, resourceID string) bool {
	for _, v := range violations {
		if v.ResourceID == resourceID && v.PolicyID == "s3_bucket_encryption" {
			return true
		}
	}
	return false
}

func firedPolicy(violations []types.PolicyViolation, resourceID, policyID string) bool {
	for _, v := range violations {
		if v.ResourceID == resourceID && v.PolicyID == policyID {
			return true
		}
	}
	return false
}

// TestS3_SplitResourceEncryptionSuppressesFalsePositive proves that a bucket
// secured by a SEPARATE aws_s3_bucket_server_side_encryption_configuration
// resource (AWS provider v4+ style) is NOT flagged for missing encryption.
func TestS3_SplitResourceEncryptionSuppressesFalsePositive(t *testing.T) {
	e := loadS3Engine(t)
	resources := []types.Resource{
		{ID: "aws_s3_bucket.modern", Type: "aws_s3_bucket", Name: "modern", Attributes: map[string]interface{}{}},
		{
			ID:   "aws_s3_bucket_server_side_encryption_configuration.modern",
			Type: "aws_s3_bucket_server_side_encryption_configuration",
			Name: "modern",
			Attributes: map[string]interface{}{
				"bucket": "aws_s3_bucket.modern.id",
			},
		},
	}
	res, err := e.Evaluate(context.Background(), resources)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if firedEncryption(res.Violations, "aws_s3_bucket.modern") {
		t.Error("encryption policy false-positived on a bucket with a split-resource encryption config")
	}
}

// TestS3_NoEncryptionStillFlagged is the recall guard: a bucket with neither
// inline encryption nor a sibling config must still be flagged.
func TestS3_NoEncryptionStillFlagged(t *testing.T) {
	e := loadS3Engine(t)
	resources := []types.Resource{
		{ID: "aws_s3_bucket.bare", Type: "aws_s3_bucket", Name: "bare", Attributes: map[string]interface{}{}},
	}
	res, err := e.Evaluate(context.Background(), resources)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !firedEncryption(res.Violations, "aws_s3_bucket.bare") {
		t.Error("encryption policy failed to flag a genuinely unencrypted bucket (recall regression)")
	}
}

// TestS3_SiblingMatchingIsNameSpecific proves the sibling check is keyed to the
// specific bucket: an encryption config for bucket B must NOT suppress the
// finding on an unrelated, unencrypted bucket A.
func TestS3_SiblingMatchingIsNameSpecific(t *testing.T) {
	e := loadS3Engine(t)
	resources := []types.Resource{
		{ID: "aws_s3_bucket.a", Type: "aws_s3_bucket", Name: "a", Attributes: map[string]interface{}{}},
		{ID: "aws_s3_bucket.b", Type: "aws_s3_bucket", Name: "b", Attributes: map[string]interface{}{}},
		{
			ID:         "aws_s3_bucket_server_side_encryption_configuration.for_b",
			Type:       "aws_s3_bucket_server_side_encryption_configuration",
			Name:       "for_b",
			Attributes: map[string]interface{}{"bucket": "aws_s3_bucket.b.id"},
		},
	}
	res, err := e.Evaluate(context.Background(), resources)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !firedEncryption(res.Violations, "aws_s3_bucket.a") {
		t.Error("bucket A (no sibling) should still be flagged; sibling matching is not name-specific")
	}
	if firedEncryption(res.Violations, "aws_s3_bucket.b") {
		t.Error("bucket B (has its sibling) should not be flagged")
	}
}

// TestS3_SiblingMatchingAvoidsPrefixCollision verifies bucket name prefix
// collisions do not suppress findings (e.g. "a" should not be matched by refs
// to "ab").
func TestS3_SiblingMatchingAvoidsPrefixCollision(t *testing.T) {
	e := loadS3Engine(t)
	resources := []types.Resource{
		{ID: "aws_s3_bucket.a", Type: "aws_s3_bucket", Name: "a", Attributes: map[string]interface{}{}},
		{ID: "aws_s3_bucket.ab", Type: "aws_s3_bucket", Name: "ab", Attributes: map[string]interface{}{}},
		{
			ID:         "aws_s3_bucket_server_side_encryption_configuration.for_ab",
			Type:       "aws_s3_bucket_server_side_encryption_configuration",
			Name:       "for_ab",
			Attributes: map[string]interface{}{"bucket": "aws_s3_bucket.ab.id"},
		},
		{
			ID:         "aws_s3_bucket_logging.for_ab",
			Type:       "aws_s3_bucket_logging",
			Name:       "for_ab",
			Attributes: map[string]interface{}{"bucket": "aws_s3_bucket.ab.id"},
		},
	}
	res, err := e.Evaluate(context.Background(), resources)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if !firedPolicy(res.Violations, "aws_s3_bucket.a", "s3_bucket_encryption") {
		t.Error("bucket 'a' should still be flagged for missing encryption; prefix collision suppressed it")
	}
	if firedPolicy(res.Violations, "aws_s3_bucket.ab", "s3_bucket_encryption") {
		t.Error("bucket 'ab' has matching encryption sibling and should not be flagged")
	}
	if !firedPolicy(res.Violations, "aws_s3_bucket.a", "s3_bucket_logging") {
		t.Error("bucket 'a' should still be flagged for missing logging; prefix collision suppressed it")
	}
	if firedPolicy(res.Violations, "aws_s3_bucket.ab", "s3_bucket_logging") {
		t.Error("bucket 'ab' has matching logging sibling and should not be flagged")
	}
}

// TestS3_CrossModuleNameCollision guards against a false negative: two modules
// that each name a bucket "this" must not cross-suppress. An encryption config
// in module A must not silence the unencrypted bucket "this" in module B.
// Sibling matching is scoped to the same module (via the _module_name attribute).
func TestS3_CrossModuleNameCollision(t *testing.T) {
	e := loadS3Engine(t)
	resources := []types.Resource{
		{ID: "module.a.aws_s3_bucket.this", Type: "aws_s3_bucket", Name: "this",
			Attributes: map[string]interface{}{"_module_name": "a"}},
		{ID: "module.a.aws_s3_bucket_server_side_encryption_configuration.this",
			Type: "aws_s3_bucket_server_side_encryption_configuration", Name: "this",
			Attributes: map[string]interface{}{"bucket": "aws_s3_bucket.this.id", "_module_name": "a"}},
		{ID: "module.b.aws_s3_bucket.this", Type: "aws_s3_bucket", Name: "this",
			Attributes: map[string]interface{}{"_module_name": "b"}},
	}
	res, err := e.Evaluate(context.Background(), resources)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !firedPolicy(res.Violations, "module.b.aws_s3_bucket.this", "s3_bucket_encryption") {
		t.Error("module B's unencrypted bucket was suppressed by module A's sibling (cross-module false negative)")
	}
	if firedPolicy(res.Violations, "module.a.aws_s3_bucket.this", "s3_bucket_encryption") {
		t.Error("module A's bucket has its own sibling and should not be flagged")
	}
}

// TestS3_LiteralBucketStringDoesNotSuppress ensures a literal bucket name in a
// sibling resource does not get treated as a Terraform resource reference.
func TestS3_LiteralBucketStringDoesNotSuppress(t *testing.T) {
	e := loadS3Engine(t)
	resources := []types.Resource{
		{ID: "aws_s3_bucket.modern", Type: "aws_s3_bucket", Name: "modern", Attributes: map[string]interface{}{}},
		{
			ID:         "aws_s3_bucket_server_side_encryption_configuration.literal",
			Type:       "aws_s3_bucket_server_side_encryption_configuration",
			Name:       "literal",
			Attributes: map[string]interface{}{"bucket": "my-bucket"},
		},
		{
			ID:         "aws_s3_bucket_logging.literal",
			Type:       "aws_s3_bucket_logging",
			Name:       "literal",
			Attributes: map[string]interface{}{"bucket": "my-bucket"},
		},
	}
	res, err := e.Evaluate(context.Background(), resources)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if !firedPolicy(res.Violations, "aws_s3_bucket.modern", "s3_bucket_encryption") {
		t.Error("literal bucket string incorrectly suppressed encryption finding")
	}
	if !firedPolicy(res.Violations, "aws_s3_bucket.modern", "s3_bucket_logging") {
		t.Error("literal bucket string incorrectly suppressed logging finding")
	}
}
