package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

func TestOPAEngine_LoadPolicy(t *testing.T) {
	engine := NewOPAEngine()
	ctx := context.Background()

	// Create a test policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test_policy.rego")
	
	policyContent := `
package policyguard.aws.s3

import future.keywords.contains
import future.keywords.if

deny[msg] {
	input.type == "aws_s3_bucket"
	input.attributes.acl == "public-read-write"
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

func TestOPAEngine_Evaluate(t *testing.T) {
	engine := NewOPAEngine()
	ctx := context.Background()

	// Create test policies
	tmpDir := t.TempDir()
	
	policies := map[string]string{
		"s3_policy.rego": `
package policyguard.aws.s3

import future.keywords.contains
import future.keywords.if

# Check for public S3 buckets
violation[result] {
	input.type == "aws_s3_bucket"
	input.attributes.acl == "public-read-write"
	result := {
		"resource_id": input.id,
		"policy_id": "aws-s3-bucket-public-access",
		"severity": "high",
		"message": "S3 bucket has public read-write access",
		"details": sprintf("Bucket '%s' allows public read-write access", [input.attributes.bucket]),
		"remediation": "Change ACL to 'private' or use bucket policies for fine-grained access control"
	}
}

# Check for unencrypted S3 buckets
violation[result] {
	input.type == "aws_s3_bucket"
	not input.attributes.server_side_encryption_configuration
	result := {
		"resource_id": input.id,
		"policy_id": "aws-s3-bucket-encryption",
		"severity": "high",
		"message": "S3 bucket does not have encryption enabled",
		"details": sprintf("Bucket '%s' is not encrypted at rest", [input.attributes.bucket]),
		"remediation": "Enable server-side encryption using SSE-S3 or SSE-KMS"
	}
}`,
		"ec2_policy.rego": `
package policyguard.aws.ec2

import future.keywords.contains
import future.keywords.if

# Check for EC2 instances with public IPs
violation[result] {
	input.type == "aws_instance"
	input.attributes.associate_public_ip_address == true
	result := {
		"resource_id": input.id,
		"policy_id": "aws-ec2-public-ip",
		"severity": "medium",
		"message": "EC2 instance has a public IP address",
		"details": "Instance is directly accessible from the internet",
		"remediation": "Use private IPs with NAT gateway or VPN for secure access"
	}
}

# Check for unencrypted root volumes
violation[result] {
	input.type == "aws_instance"
	input.attributes.root_block_device.encrypted == false
	result := {
		"resource_id": input.id,
		"policy_id": "aws-ec2-encryption",
		"severity": "high",
		"message": "EC2 root volume is not encrypted",
		"details": "Root block device encryption is disabled",
		"remediation": "Enable encryption for root block device"
	}
}`,
	}

	// Write policy files
	for filename, content := range policies {
		policyFile := filepath.Join(tmpDir, filename)
		err := os.WriteFile(policyFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create policy file %s: %v", filename, err)
		}
	}

	// Load policies
	err := engine.LoadPoliciesFromDirectory(ctx, tmpDir)
	if err != nil {
		t.Fatalf("LoadPoliciesFromDirectory() error = %v", err)
	}

	// Test cases
	tests := []struct {
		name      string
		resources []types.Resource
		wantPass  bool
		wantCount int
	}{
		{
			name: "secure resources",
			resources: []types.Resource{
				{
					ID:       "aws_s3_bucket.secure",
					Type:     "aws_s3_bucket",
					Provider: "aws",
					Name:     "secure",
					Attributes: map[string]interface{}{
						"bucket": "my-secure-bucket",
						"acl":    "private",
						"server_side_encryption_configuration": map[string]interface{}{
							"rule": map[string]interface{}{
								"apply_server_side_encryption_by_default": map[string]interface{}{
									"sse_algorithm": "AES256",
								},
							},
						},
					},
				},
				{
					ID:       "aws_instance.secure",
					Type:     "aws_instance",
					Provider: "aws",
					Name:     "secure",
					Attributes: map[string]interface{}{
						"ami":                         "ami-12345678",
						"instance_type":               "t2.micro",
						"associate_public_ip_address": false,
						"root_block_device": map[string]interface{}{
							"encrypted": true,
						},
					},
				},
			},
			wantPass:  true,
			wantCount: 0,
		},
		{
			name: "insecure S3 bucket",
			resources: []types.Resource{
				{
					ID:       "aws_s3_bucket.insecure",
					Type:     "aws_s3_bucket",
					Provider: "aws",
					Name:     "insecure",
					Attributes: map[string]interface{}{
						"bucket": "my-insecure-bucket",
						"acl":    "public-read-write",
					},
				},
			},
			wantPass:  false,
			wantCount: 2, // public access + no encryption
		},
		{
			name: "insecure EC2 instance",
			resources: []types.Resource{
				{
					ID:       "aws_instance.insecure",
					Type:     "aws_instance",
					Provider: "aws",
					Name:     "insecure",
					Attributes: map[string]interface{}{
						"ami":                         "ami-12345678",
						"instance_type":               "t2.micro",
						"associate_public_ip_address": true,
						"root_block_device": map[string]interface{}{
							"encrypted": false,
						},
					},
				},
			},
			wantPass:  false,
			wantCount: 2, // public IP + unencrypted volume
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Evaluate(ctx, tt.resources)
			if err != nil {
				t.Errorf("Evaluate() error = %v", err)
				return
			}

			if result.Passed != tt.wantPass {
				t.Errorf("Evaluate() passed = %v, want %v", result.Passed, tt.wantPass)
			}

			if len(result.Violations) != tt.wantCount {
				t.Errorf("Evaluate() returned %d violations, want %d", len(result.Violations), tt.wantCount)
			}
		})
	}
}

func TestOPAEngine_GetLoadedPolicies(t *testing.T) {
	engine := NewOPAEngine()
	ctx := context.Background()

	// Initially should have no policies
	policies := engine.GetLoadedPolicies()
	if len(policies) != 0 {
		t.Errorf("Expected 0 loaded policies initially, got %d", len(policies))
	}

	// Create test policies
	tmpDir := t.TempDir()
	
	policyFiles := []string{"policy1.rego", "policy2.rego", "policy3.rego"}
	policyContent := `
package test

default allow = false
`

	for _, filename := range policyFiles {
		policyFile := filepath.Join(tmpDir, filename)
		err := os.WriteFile(policyFile, []byte(policyContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create policy file %s: %v", filename, err)
		}
	}

	// Load policies
	err := engine.LoadPoliciesFromDirectory(ctx, tmpDir)
	if err != nil {
		t.Fatalf("LoadPoliciesFromDirectory() error = %v", err)
	}

	// Should have 3 policies loaded
	policies = engine.GetLoadedPolicies()
	if len(policies) != 3 {
		t.Errorf("Expected 3 loaded policies, got %d", len(policies))
	}
}