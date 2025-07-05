package human

import (
	"context"
	"testing"
	"time"

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
			name: "single violation, single resource",
			violations: []types.PolicyViolation{
				{
					ID:         "violation-1",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_encryption",
					Severity:   "high",
					Message:    "S3 bucket not encrypted",
				},
			},
			expected: 1,
		},
		{
			name: "multiple violations, single resource",
			violations: []types.PolicyViolation{
				{
					ID:         "violation-1",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_encryption",
					Severity:   "high",
					Message:    "S3 bucket not encrypted",
				},
				{
					ID:         "violation-2",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_logging",
					Severity:   "medium",
					Message:    "S3 bucket logging not enabled",
				},
			},
			expected: 1, // Same resource, so count = 1
		},
		{
			name: "multiple violations, multiple resources",
			violations: []types.PolicyViolation{
				{
					ID:         "violation-1",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_encryption",
					Severity:   "high",
					Message:    "S3 bucket not encrypted",
				},
				{
					ID:         "violation-2",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_logging",
					Severity:   "medium",
					Message:    "S3 bucket logging not enabled",
				},
				{
					ID:         "violation-3",
					ResourceID: "aws_instance.instance1",
					PolicyID:   "ec2_encryption",
					Severity:   "high",
					Message:    "EC2 instance not encrypted",
				},
			},
			expected: 2, // Two different resources
		},
		{
			name: "many violations, three resources",
			violations: []types.PolicyViolation{
				{
					ID:         "violation-1",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_encryption",
					Severity:   "high",
				},
				{
					ID:         "violation-2",
					ResourceID: "aws_s3_bucket.bucket1",
					PolicyID:   "s3_logging",
					Severity:   "medium",
				},
				{
					ID:         "violation-3",
					ResourceID: "aws_instance.instance1",
					PolicyID:   "ec2_encryption",
					Severity:   "high",
				},
				{
					ID:         "violation-4",
					ResourceID: "aws_instance.instance1",
					PolicyID:   "ec2_imds",
					Severity:   "high",
				},
				{
					ID:         "violation-5",
					ResourceID: "aws_security_group.sg1",
					PolicyID:   "sg_ssh_open",
					Severity:   "critical",
				},
			},
			expected: 3, // Three different resources
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
		description  string
	}{
		{
			name:         "no resources, no violations",
			resources:    []types.Resource{},
			violations:   []types.PolicyViolation{},
			expectedRate: 100.0, // No resources means 100% pass rate
			description:  "Empty case should return 100%",
		},
		{
			name: "all resources clean",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1", Type: "aws_s3_bucket"},
				{ID: "aws_instance.instance1", Type: "aws_instance"},
				{ID: "aws_security_group.sg1", Type: "aws_security_group"},
			},
			violations:   []types.PolicyViolation{},
			expectedRate: 100.0,
			description:  "All clean resources should be 100%",
		},
		{
			name: "all resources have violations",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1", Type: "aws_s3_bucket"},
				{ID: "aws_instance.instance1", Type: "aws_instance"},
			},
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_instance.instance1", PolicyID: "ec2_encryption"},
			},
			expectedRate: 0.0,
			description:  "All failing resources should be 0%",
		},
		{
			name: "single resource with multiple violations",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1", Type: "aws_s3_bucket"},
				{ID: "aws_instance.instance1", Type: "aws_instance"},
				{ID: "aws_security_group.sg1", Type: "aws_security_group"},
			},
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_logging"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_versioning"},
			},
			expectedRate: 66.66666666666666, // (3-1)/3 * 100
			description:  "Multiple violations on one resource should count as one failing resource",
		},
		{
			name: "realistic scenario: 3 resources, 5 violations across 2 resources",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1", Type: "aws_s3_bucket"},
				{ID: "aws_s3_bucket_acl.bucket1_acl", Type: "aws_s3_bucket_acl"},
				{ID: "aws_instance.instance1", Type: "aws_instance"},
			},
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_logging"},
				{ResourceID: "aws_instance.instance1", PolicyID: "ec2_encryption"},
				{ResourceID: "aws_instance.instance1", PolicyID: "ec2_imds"},
				{ResourceID: "aws_instance.instance1", PolicyID: "ec2_public_ip"},
			},
			expectedRate: 33.33333333333333, // (3-2)/3 * 100
			description:  "Real-world scenario from our examples",
		},
		{
			name: "edge case: more violations than resources",
			resources: []types.Resource{
				{ID: "aws_s3_bucket.bucket1", Type: "aws_s3_bucket"},
			},
			violations: []types.PolicyViolation{
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_encryption"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_logging"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_versioning"},
				{ResourceID: "aws_s3_bucket.bucket1", PolicyID: "s3_lifecycle"},
			},
			expectedRate: 0.0, // (1-1)/1 * 100
			description:  "Multiple violations on single resource should still work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create policy result
			policyResult := &types.PolicyResult{
				Passed:     len(tt.violations) == 0,
				Violations: tt.violations,
				Metadata:   map[string]interface{}{},
			}

			// Generate report
			report, err := reporter.Generate(ctx, policyResult, tt.resources)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			// Check pass rate
			if report.Summary.PassRate != tt.expectedRate {
				t.Errorf("PassRate = %v, expected %v (%s)", 
					report.Summary.PassRate, tt.expectedRate, tt.description)
			}

			// Verify other summary fields
			if report.Summary.TotalResources != len(tt.resources) {
				t.Errorf("TotalResources = %v, expected %v", 
					report.Summary.TotalResources, len(tt.resources))
			}

			if report.Summary.TotalViolations != len(tt.violations) {
				t.Errorf("TotalViolations = %v, expected %v", 
					report.Summary.TotalViolations, len(tt.violations))
			}
		})
	}
}

func TestReporter_Generate(t *testing.T) {
	reporter := New()
	ctx := context.Background()

	resources := []types.Resource{
		{
			ID:       "aws_s3_bucket.test",
			Type:     "aws_s3_bucket",
			Provider: "aws",
			Name:     "test",
		},
	}

	violations := []types.PolicyViolation{
		{
			ID:          "test-violation",
			ResourceID:  "aws_s3_bucket.test",
			PolicyID:    "s3_encryption",
			Severity:    "high",
			Message:     "Test violation",
			Details:     "Test details",
			Remediation: "Test remediation",
			Location: types.Location{
				File:   "test.tf",
				Line:   1,
				Column: 1,
			},
			Timestamp: time.Now(),
		},
	}

	policyResult := &types.PolicyResult{
		Passed:     false,
		Violations: violations,
		Metadata:   map[string]interface{}{},
	}

	report, err := reporter.Generate(ctx, policyResult, resources)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify report structure
	if report.ID == "" {
		t.Error("Report ID should not be empty")
	}

	if report.Timestamp.IsZero() {
		t.Error("Report timestamp should not be zero")
	}

	if len(report.Resources) != len(resources) {
		t.Errorf("Report resources count = %v, expected %v", len(report.Resources), len(resources))
	}

	if len(report.Violations) != len(violations) {
		t.Errorf("Report violations count = %v, expected %v", len(report.Violations), len(violations))
	}

	// Verify summary
	expectedPassRate := 0.0 // 1 resource, 1 resource with violations = (1-1)/1 * 100 = 0%
	if report.Summary.PassRate != expectedPassRate {
		t.Errorf("Summary PassRate = %v, expected %v", report.Summary.PassRate, expectedPassRate)
	}

	if report.Summary.TotalResources != 1 {
		t.Errorf("Summary TotalResources = %v, expected 1", report.Summary.TotalResources)
	}

	if report.Summary.TotalViolations != 1 {
		t.Errorf("Summary TotalViolations = %v, expected 1", report.Summary.TotalViolations)
	}

	// Check violations by severity
	if report.Summary.ViolationsBySeverity["high"] != 1 {
		t.Errorf("High severity violations = %v, expected 1", report.Summary.ViolationsBySeverity["high"])
	}
}

func TestReporter_Format(t *testing.T) {
	reporter := New()
	
	format := reporter.Format()
	if format != "human" {
		t.Errorf("Format() = %v, expected 'human'", format)
	}
}