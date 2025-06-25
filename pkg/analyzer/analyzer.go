package analyzer

import (
	"context"
	"github.com/policyguard/policyguard/pkg/parser"
	"github.com/policyguard/policyguard/pkg/policy"
	"github.com/policyguard/policyguard/pkg/remediation"
	"github.com/policyguard/policyguard/pkg/reporter"
	"github.com/policyguard/policyguard/pkg/types"
)

// Analyzer coordinates the analysis workflow
type Analyzer struct {
	parser     parser.Parser
	engine     policy.Engine
	suggester  remediation.Suggester
	reporter   reporter.Reporter
}

// New creates a new analyzer instance
func New(parser parser.Parser, engine policy.Engine, suggester remediation.Suggester, reporter reporter.Reporter) *Analyzer {
	return &Analyzer{
		parser:    parser,
		engine:    engine,
		suggester: suggester,
		reporter:  reporter,
	}
}

// AnalyzeFile analyzes a single file
func (a *Analyzer) AnalyzeFile(ctx context.Context, filePath string) (*types.Report, error) {
	// Parse resources from file
	resources, err := a.parser.Parse(ctx, filePath)
	if err != nil {
		return nil, err
	}
	
	// Evaluate policies
	result, err := a.engine.Evaluate(ctx, resources)
	if err != nil {
		return nil, err
	}
	
	// Generate report
	report, err := a.reporter.Generate(ctx, result, resources)
	if err != nil {
		return nil, err
	}
	
	return report, nil
}

// AnalyzeDirectory analyzes all files in a directory
func (a *Analyzer) AnalyzeDirectory(ctx context.Context, dirPath string) (*types.Report, error) {
	// Parse all resources from directory
	resources, err := a.parser.ParseDirectory(ctx, dirPath)
	if err != nil {
		return nil, err
	}
	
	// Evaluate policies
	result, err := a.engine.Evaluate(ctx, resources)
	if err != nil {
		return nil, err
	}
	
	// Generate report
	report, err := a.reporter.Generate(ctx, result, resources)
	if err != nil {
		return nil, err
	}
	
	return report, nil
}