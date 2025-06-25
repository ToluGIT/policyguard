package policy

import (
	"context"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// Engine defines the interface for policy evaluation
type Engine interface {
	// Evaluate evaluates resources against loaded policies
	Evaluate(ctx context.Context, resources []types.Resource) (*types.PolicyResult, error)
	
	// LoadPolicy loads a policy from the given path
	LoadPolicy(ctx context.Context, policyPath string) error
	
	// LoadPoliciesFromDirectory loads all policies from a directory
	LoadPoliciesFromDirectory(ctx context.Context, dirPath string) error
	
	// GetLoadedPolicies returns the IDs of all loaded policies
	GetLoadedPolicies() []string
}

// Policy represents a security policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Provider    string                 `json:"provider"`
	Resource    string                 `json:"resource"`
	Severity    string                 `json:"severity"`
	Rule        string                 `json:"rule"`
	Metadata    map[string]interface{} `json:"metadata"`
}