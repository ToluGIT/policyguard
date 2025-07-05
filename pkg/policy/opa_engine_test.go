package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/policy/opa"
	"github.com/ToluGIT/policyguard/pkg/types"
)

func TestOPAEngine_LoadPolicy(t *testing.T) {
	engine := opa.New()
	ctx := context.Background()

	// Create a test policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test_policy.rego")
	
	policyContent := `
package policyguard.aws.s3

import future.keywords.contains
import future.keywords.if

deny[msg] {
	input.resource.type == "aws_s3_bucket"
	input.resource.attributes.acl == "public-read-write"
	msg := "S3 bucket has public read-write access"
}
`
	
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}
	
	// Test loading the policy
	err = engine.LoadPolicy(ctx, policyFile)
	if err != nil {
		t.Errorf("LoadPolicy() error = %v", err)
	}
	
	// Verify policy was loaded
	policies := engine.GetLoadedPolicies()
	if len(policies) != 1 {
		t.Errorf("Expected 1 loaded policy, got %d", len(policies))
	}
}

func TestOPAEngine_Basic(t *testing.T) {
	engine := opa.New()
	ctx := context.Background()

	// Test with no policies loaded - should return error
	resources := []types.Resource{
		{
			ID:       "aws_s3_bucket.test",
			Type:     "aws_s3_bucket",
			Provider: "aws",
			Name:     "test",
		},
	}
	
	_, err := engine.Evaluate(ctx, resources)
	if err == nil {
		t.Error("Expected error when no policies loaded, got nil")
	}
}

func TestOPAEngine_GetLoadedPolicies(t *testing.T) {
	engine := opa.New()

	// Initially should have no policies
	policies := engine.GetLoadedPolicies()
	if len(policies) != 0 {
		t.Errorf("Expected 0 loaded policies initially, got %d", len(policies))
	}
}

func TestOPAEngine_LoadPoliciesFromDirectory_NotFound(t *testing.T) {
	engine := opa.New()
	ctx := context.Background()

	// Test with non-existent directory - it will try embedded policies first
	// so we expect it to either succeed (if embedded policies exist) or fail appropriately
	err := engine.LoadPoliciesFromDirectory(ctx, "/non/existent/path")
	// The error is expected since there are no embedded policies or directory
	if err == nil {
		// If no error, embedded policies were loaded successfully
		policies := engine.GetLoadedPolicies()
		if len(policies) == 0 {
			t.Error("Expected either error or loaded policies, got neither")
		}
	}
	// If error exists, that's expected behavior for missing directory and no embedded policies
}