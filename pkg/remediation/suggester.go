package remediation

import (
	"context"
	"github.com/policyguard/policyguard/pkg/types"
)

// Suggester defines the interface for generating remediation suggestions
type Suggester interface {
	// Suggest generates remediation suggestions for violations
	Suggest(ctx context.Context, violation types.PolicyViolation, resource types.Resource) (*Suggestion, error)
	
	// SuggestBatch generates suggestions for multiple violations
	SuggestBatch(ctx context.Context, violations []types.PolicyViolation, resources []types.Resource) ([]*Suggestion, error)
}

// Suggestion represents a remediation suggestion
type Suggestion struct {
	ViolationID string   `json:"violation_id"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	CodeFix     *CodeFix `json:"code_fix,omitempty"`
	References  []string `json:"references,omitempty"`
}

// CodeFix represents a suggested code change
type CodeFix struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	OldContent  string `json:"old_content"`
	NewContent  string `json:"new_content"`
	Explanation string `json:"explanation"`
}