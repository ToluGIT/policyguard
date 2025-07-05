package json

import (
	"context"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

func TestReporter_countResourcesWithViolations(t *testing.T) {
	reporter := New()

	tests := []struct {
		name       string
		violations []types.PolicyViolation
		expected   int
	}{
		{
			name:       "no violations",
			violations: []types.PolicyViolation{},
			expected:   0,
		},
		{
			name: "multiple violations, single resource",
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_logging"},
			},
			expected: 1,
		},
		{
			name: "multiple violations, multiple resources",
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_instance.instance1", PolicyID: "ec2_encryption"},
				{ResourceID: "aws_security_group.sg1", PolicyID: "sg_ssh_open"},
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reporter.countResourcesWithViolations(tt.violations)
			if result != tt.expected {
				t.Errorf("countResourcesWithViolations() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestReporter_PassRateCalculation(t *testing.T) {
	reporter := New()
	ctx := context.Background()

	tests := []struct {
		name         string
		resources    []types.Resource
		violations   []types.PolicyViolation
		expectedRate float64
	}{
		{
			name:         "no resources",
			resources:    []types.Resource{},
			violations:   []types.PolicyViolation{},
			expectedRate: 100.0,
		},
		{
			name: "all resources clean",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1"},
				{ID: "aws_instance.instance1"},
			},
			violations:   []types.PolicyViolation{},
			expectedRate: 100.0,
		},
		{
			name: "realistic scenario",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1"},
				{ID: "aws_s3_bucket_acl.bucket1_acl"},
				{ID: "aws_instance.instance1"},
			},
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_logging"},
				{ResourceID: "aws_instance.instance1", PolicyID: "ec2_encryption"},
			},
			expectedRate: 33.33333333333333, // (3-2)/3 * 100
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyResult := &types.PolicyResult{
				Passed:     len(tt.violations) == 0,
				Violations: tt.violations,
			}

			report, err := reporter.Generate(ctx, policyResult, tt.resources)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if report.Summary.PassRate != tt.expectedRate {
				t.Errorf("PassRate = %v, expected %v", 
					report.Summary.PassRate, tt.expectedRate)
			}
		})
	}
}

func TestReporter_Format(t *testing.T) {
	reporter := New()
	
	format := reporter.Format()
	if format != "json" {
		t.Errorf("Format() = %v, expected 'json'", format)
	}
}