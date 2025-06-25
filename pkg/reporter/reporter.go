package reporter

import (
	"context"
	"io"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter defines the interface for generating reports
type Reporter interface {
	// Generate creates a report from policy results
	Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error)
	
	// Write writes the report to the given writer
	Write(ctx context.Context, report *types.Report, writer io.Writer) error
	
	// Format returns the format this reporter outputs
	Format() string
}

// ReporterFactory creates reporter instances
type ReporterFactory interface {
	// GetReporter returns a reporter for the given format
	GetReporter(format string) (Reporter, error)
	
	// RegisterReporter registers a new reporter
	RegisterReporter(format string, reporter Reporter) error
	
	// AvailableFormats returns all available report formats
	AvailableFormats() []string
}