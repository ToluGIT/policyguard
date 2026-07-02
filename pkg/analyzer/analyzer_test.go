package analyzer

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/config"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// Mock parser
type mockParser struct {
	resources []types.Resource
	err       error
}

func (m *mockParser) Parse(ctx context.Context, filePath string) ([]types.Resource, error) {
	return m.resources, m.err
}

func (m *mockParser) ParseDirectory(ctx context.Context, dirPath string) ([]types.Resource, error) {
	return m.resources, m.err
}

func (m *mockParser) SupportedExtensions() []string {
	return []string{".tf", ".tofu"}
}

// Mock policy engine
type mockEngine struct {
	result *types.PolicyResult
	err    error
}

func (m *mockEngine) Evaluate(ctx context.Context, resources []types.Resource) (*types.PolicyResult, error) {
	return m.result, m.err
}

func (m *mockEngine) LoadPolicy(ctx context.Context, policyPath string) error {
	return nil
}

func (m *mockEngine) LoadPoliciesFromDirectory(ctx context.Context, dirPath string) error {
	return nil
}

func (m *mockEngine) GetLoadedPolicies() []string {
	return []string{"test-policy"}
}

// WithSeverityConfig implements the policy.Engine interface
func (m *mockEngine) WithSeverityConfig(configPath string) error {
	return nil
}

// Mock reporter
type mockReporter struct {
	report *types.Report
	err    error
}

func (m *mockReporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	return m.report, m.err
}

func (m *mockReporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	return nil
}

func (m *mockReporter) Format() string {
	return "mock"
}

func TestSortViolations_Deterministic(t *testing.T) {
	// Two different input orderings of the same findings must sort to the same
	// canonical order, so reports are stable across filesystem-dependent
	// discovery order.
	mk := func() []types.PolicyViolation {
		return []types.PolicyViolation{
			{ID: "b", PolicyID: "p2", ResourceID: "aws_s3_bucket.z", Location: types.Location{File: "b.tf", Line: 5}},
			{ID: "a", PolicyID: "p1", ResourceID: "aws_s3_bucket.a", Location: types.Location{File: "a.tf", Line: 3}},
			{ID: "c", PolicyID: "p1", ResourceID: "aws_s3_bucket.a", Location: types.Location{File: "a.tf", Line: 3}},
		}
	}
	v1 := mk()
	v2 := []types.PolicyViolation{mk()[2], mk()[0], mk()[1]} // shuffled

	sortViolations(v1)
	sortViolations(v2)

	if len(v1) != len(v2) {
		t.Fatalf("length mismatch")
	}
	for i := range v1 {
		if v1[i].ID != v2[i].ID {
			t.Errorf("position %d differs after sort: %q vs %q (not deterministic)", i, v1[i].ID, v2[i].ID)
		}
	}
	// First should be the a.tf finding (file ordering wins).
	if v1[0].Location.File != "a.tf" {
		t.Errorf("sort key wrong: first file = %q, want a.tf", v1[0].Location.File)
	}
}

func TestAnalyzer_Suppressions(t *testing.T) {
	ctx := context.Background()
	resources := []types.Resource{{ID: "aws_s3_bucket.b", Type: "aws_s3_bucket", Name: "b"}}
	violations := []types.PolicyViolation{
		{ID: "v1", PolicyID: "s3_bucket_logging", ResourceID: "aws_s3_bucket.b", Severity: "medium"},
		{ID: "v2", PolicyID: "s3_bucket_encryption", ResourceID: "aws_s3_bucket.b", Severity: "high"},
	}

	parser := &mockParser{resources: resources}
	engine := &mockEngine{result: &types.PolicyResult{Violations: violations}}
	reporter := &mockReporter{report: &types.Report{}}

	a := New(parser, engine, nil, reporter).WithSuppressions(&config.SuppressionConfig{
		Rules: []config.SuppressionRule{
			{PolicyID: "s3_bucket_logging", Reason: "handled centrally"},
		},
	})

	// The reporter records what it was handed; capture via a custom reporter.
	captured := &capturingReporter{}
	a.reporter = captured

	if _, err := a.AnalyzeFile(ctx, "main.tf"); err != nil {
		t.Fatalf("AnalyzeFile: %v", err)
	}

	if len(captured.result.Violations) != 1 {
		t.Fatalf("expected 1 violation after suppression, got %d", len(captured.result.Violations))
	}
	if captured.result.Violations[0].PolicyID != "s3_bucket_encryption" {
		t.Errorf("wrong violation kept: %s", captured.result.Violations[0].PolicyID)
	}
	if c, _ := captured.result.Metadata["suppressed_count"].(int); c != 1 {
		t.Errorf("suppressed_count = %v, want 1", captured.result.Metadata["suppressed_count"])
	}
	byPolicy, _ := captured.result.Metadata["suppressed_by_policy"].(map[string]int)
	if byPolicy["s3_bucket_logging"] != 1 {
		t.Errorf("suppressed_by_policy = %v, want s3_bucket_logging:1", byPolicy)
	}
}

// capturingReporter records the PolicyResult passed to Generate so tests can
// assert on post-suppression violations and metadata.
type capturingReporter struct {
	result *types.PolicyResult
}

func (c *capturingReporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	c.result = result
	return &types.Report{Violations: result.Violations, Metadata: result.Metadata}, nil
}
func (c *capturingReporter) Write(ctx context.Context, report *types.Report, w io.Writer) error {
	return nil
}
func (c *capturingReporter) Format() string { return "capture" }

func TestAnalyzer_New(t *testing.T) {
	parser := &mockParser{}
	engine := &mockEngine{}
	reporter := &mockReporter{}

	analyzer := New(parser, engine, nil, reporter)

	if analyzer == nil {
		t.Error("New() returned nil")
	}
	if analyzer.parser != parser {
		t.Error("Parser not set correctly")
	}
	if analyzer.engine != engine {
		t.Error("Engine not set correctly")
	}
	if analyzer.reporter.Format() != reporter.Format() {
		t.Error("Reporter not set correctly")
	}
}

func TestAnalyzer_AnalyzeFile(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		parser         *mockParser
		engine         *mockEngine
		reporter       *mockReporter
		expectedReport *types.Report
		wantErr        bool
	}{
		{
			name: "successful analysis",
			parser: &mockParser{
				resources: []types.Resource{
					{
						ID:       "aws_s3_bucket.test",
						Type:     "aws_s3_bucket",
						Provider: "aws",
						Name:     "test",
						Attributes: map[string]interface{}{
							"bucket": "test-bucket",
						},
					},
				},
			},
			engine: &mockEngine{
				result: &types.PolicyResult{
					Passed: true,
					Violations: []types.PolicyViolation{
						{
							ID:       "test-violation",
							PolicyID: "test-policy",
							Severity: "high",
							Message:  "Test violation",
						},
					},
				},
			},
			reporter: &mockReporter{
				report: &types.Report{
					Summary: types.Summary{
						TotalResources:  1,
						TotalViolations: 1,
						PassRate:        0.0,
					},
					Violations: []types.PolicyViolation{
						{
							ID:       "test-violation",
							PolicyID: "test-policy",
							Severity: "high",
							Message:  "Test violation",
						},
					},
				},
			},
			expectedReport: &types.Report{
				Summary: types.Summary{
					TotalResources:  1,
					TotalViolations: 1,
					PassRate:        0.0,
				},
				Violations: []types.PolicyViolation{
					{
						ID:       "test-violation",
						PolicyID: "test-policy",
						Severity: "high",
						Message:  "Test violation",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "parser error",
			parser: &mockParser{
				err: errors.New("failed to parse file"),
			},
			engine:   &mockEngine{},
			reporter: &mockReporter{},
			wantErr:  true,
		},
		{
			name: "engine error",
			parser: &mockParser{
				resources: []types.Resource{
					{
						ID:   "aws_s3_bucket.test",
						Type: "aws_s3_bucket",
					},
				},
			},
			engine: &mockEngine{
				err: errors.New("failed to evaluate policies"),
			},
			reporter: &mockReporter{},
			wantErr:  true,
		},
		{
			name: "reporter error",
			parser: &mockParser{
				resources: []types.Resource{
					{
						ID:   "aws_s3_bucket.test",
						Type: "aws_s3_bucket",
					},
				},
			},
			engine: &mockEngine{
				result: &types.PolicyResult{
					Passed:     true,
					Violations: []types.PolicyViolation{},
				},
			},
			reporter: &mockReporter{
				err: errors.New("failed to generate report"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := New(tt.parser, tt.engine, nil, tt.reporter)

			report, err := analyzer.AnalyzeFile(ctx, "test.tf")

			if (err != nil) != tt.wantErr {
				t.Errorf("AnalyzeFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if report == nil {
					t.Error("AnalyzeFile() returned nil report")
					return
				}
				if report.Summary.TotalResources != tt.expectedReport.Summary.TotalResources {
					t.Errorf("AnalyzeFile() TotalResources = %v, want %v",
						report.Summary.TotalResources, tt.expectedReport.Summary.TotalResources)
				}
				if len(report.Violations) != len(tt.expectedReport.Violations) {
					t.Errorf("AnalyzeFile() violations count = %v, want %v",
						len(report.Violations), len(tt.expectedReport.Violations))
				}
			}
		})
	}
}

func TestAnalyzer_AnalyzeDirectory(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		parser         *mockParser
		engine         *mockEngine
		reporter       *mockReporter
		expectedReport *types.Report
		wantErr        bool
	}{
		{
			name: "successful directory analysis",
			parser: &mockParser{
				resources: []types.Resource{
					{
						ID:       "aws_s3_bucket.test1",
						Type:     "aws_s3_bucket",
						Provider: "aws",
						Name:     "test1",
					},
					{
						ID:       "aws_instance.test2",
						Type:     "aws_instance",
						Provider: "aws",
						Name:     "test2",
					},
				},
			},
			engine: &mockEngine{
				result: &types.PolicyResult{
					Passed: false,
					Violations: []types.PolicyViolation{
						{
							ID:       "s3-violation",
							PolicyID: "s3-policy",
							Severity: "high",
							Message:  "S3 bucket violation",
						},
						{
							ID:       "ec2-violation",
							PolicyID: "ec2-policy",
							Severity: "medium",
							Message:  "EC2 instance violation",
						},
					},
				},
			},
			reporter: &mockReporter{
				report: &types.Report{
					Summary: types.Summary{
						TotalResources:  2,
						TotalViolations: 2,
						PassRate:        0.0,
					},
					Violations: []types.PolicyViolation{
						{
							ID:       "s3-violation",
							PolicyID: "s3-policy",
							Severity: "high",
							Message:  "S3 bucket violation",
						},
						{
							ID:       "ec2-violation",
							PolicyID: "ec2-policy",
							Severity: "medium",
							Message:  "EC2 instance violation",
						},
					},
				},
			},
			expectedReport: &types.Report{
				Summary: types.Summary{
					TotalResources:  2,
					TotalViolations: 2,
					PassRate:        0.0,
				},
				Violations: []types.PolicyViolation{
					{
						ID:       "s3-violation",
						PolicyID: "s3-policy",
						Severity: "high",
						Message:  "S3 bucket violation",
					},
					{
						ID:       "ec2-violation",
						PolicyID: "ec2-policy",
						Severity: "medium",
						Message:  "EC2 instance violation",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty directory",
			parser: &mockParser{
				resources: []types.Resource{},
			},
			engine: &mockEngine{
				result: &types.PolicyResult{
					Passed:     true,
					Violations: []types.PolicyViolation{},
				},
			},
			reporter: &mockReporter{
				report: &types.Report{
					Summary: types.Summary{
						TotalResources:  0,
						TotalViolations: 0,
						PassRate:        100.0,
					},
					Violations: []types.PolicyViolation{},
				},
			},
			expectedReport: &types.Report{
				Summary: types.Summary{
					TotalResources:  0,
					TotalViolations: 0,
					PassRate:        100.0,
				},
				Violations: []types.PolicyViolation{},
			},
			wantErr: false,
		},
		{
			name: "parser directory error",
			parser: &mockParser{
				err: errors.New("failed to parse directory"),
			},
			engine:   &mockEngine{},
			reporter: &mockReporter{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := New(tt.parser, tt.engine, nil, tt.reporter)

			report, err := analyzer.AnalyzeDirectory(ctx, "./test-dir")

			if (err != nil) != tt.wantErr {
				t.Errorf("AnalyzeDirectory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if report == nil {
					t.Error("AnalyzeDirectory() returned nil report")
					return
				}
				if report.Summary.TotalResources != tt.expectedReport.Summary.TotalResources {
					t.Errorf("AnalyzeDirectory() TotalResources = %v, want %v",
						report.Summary.TotalResources, tt.expectedReport.Summary.TotalResources)
				}
				if len(report.Violations) != len(tt.expectedReport.Violations) {
					t.Errorf("AnalyzeDirectory() violations count = %v, want %v",
						len(report.Violations), len(tt.expectedReport.Violations))
				}
			}
		})
	}
}
