package opa

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/ToluGIT/policyguard/pkg/types"
)

// Engine implements the policy.Engine interface using OPA
type Engine struct {
	compiler *ast.Compiler
	store    storage.Store
	policies map[string]*Policy
}

// Policy represents a loaded OPA policy
type Policy struct {
	ID       string
	Module   *ast.Module
	Metadata map[string]interface{}
}

// New creates a new OPA engine
func New() *Engine {
	return &Engine{
		store:    inmem.New(),
		policies: make(map[string]*Policy),
	}
}

// Evaluate evaluates resources against loaded policies
func (e *Engine) Evaluate(ctx context.Context, resources []types.Resource) (*types.PolicyResult, error) {
	if e.compiler == nil {
		return nil, fmt.Errorf("no policies loaded")
	}

	violations := []types.PolicyViolation{}

	// Evaluate each resource against all policies
	for _, resource := range resources {
		resourceViolations, err := e.evaluateResource(ctx, resource)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate resource %s: %w", resource.ID, err)
		}
		violations = append(violations, resourceViolations...)
	}

	result := &types.PolicyResult{
		Passed:     len(violations) == 0,
		Violations: violations,
		Metadata: map[string]interface{}{
			"engine":         "opa",
			"policies_count": len(e.policies),
		},
	}

	return result, nil
}

// evaluateResource evaluates a single resource against all policies
func (e *Engine) evaluateResource(ctx context.Context, resource types.Resource) ([]types.PolicyViolation, error) {
	violations := []types.PolicyViolation{}

	// Prepare input for OPA
	input := map[string]interface{}{
		"resource": map[string]interface{}{
			"id":         resource.ID,
			"type":       resource.Type,
			"provider":   resource.Provider,
			"name":       resource.Name,
			"attributes": resource.Attributes,
			"location":   resource.Location,
		},
	}

	// Query format: data.policyguard.deny[x]
	query := "data.policyguard.deny[x]"

	// Create rego instance
	r := rego.New(
		rego.Query(query),
		rego.Compiler(e.compiler),
		rego.Input(input),
		rego.Store(e.store),
	)

	// Execute query
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate rego: %w", err)
	}

	// Process results
	for _, result := range rs {
		for _, expr := range result.Expressions {
			// OPA returns a single violation object, not an array
			if v, ok := expr.Value.(map[string]interface{}); ok {
				violation, err := e.parseViolation(v, resource)
				if err != nil {
					continue
				}
				violations = append(violations, *violation)
			}
		}
	}

	return violations, nil
}

// parseViolation parses a violation from OPA result
func (e *Engine) parseViolation(v interface{}, resource types.Resource) (*types.PolicyViolation, error) {
	vMap, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid violation format")
	}

	violation := &types.PolicyViolation{
		ResourceID: resource.ID,
		Location:   resource.Location,
	}

	// Extract fields from violation map
	if id, ok := vMap["id"].(string); ok {
		violation.ID = id
	}
	if policyID, ok := vMap["policy_id"].(string); ok {
		violation.PolicyID = policyID
	}
	if severity, ok := vMap["severity"].(string); ok {
		violation.Severity = severity
	}
	if message, ok := vMap["message"].(string); ok {
		violation.Message = message
	}
	if details, ok := vMap["details"].(string); ok {
		violation.Details = details
	}
	if remediation, ok := vMap["remediation"].(string); ok {
		violation.Remediation = remediation
	}

	return violation, nil
}

// LoadPolicy loads a policy from the given path
func (e *Engine) LoadPolicy(ctx context.Context, policyPath string) error {
	content, err := ioutil.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	// Parse the module
	module, err := ast.ParseModule(policyPath, string(content))
	if err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// Extract policy ID from filename
	policyID := strings.TrimSuffix(filepath.Base(policyPath), filepath.Ext(policyPath))

	// Store the policy
	e.policies[policyID] = &Policy{
		ID:     policyID,
		Module: module,
	}

	// Recompile all policies
	return e.compile()
}

// LoadPoliciesFromDirectory loads all policies from a directory
func (e *Engine) LoadPoliciesFromDirectory(ctx context.Context, dirPath string) error {
	// Find all .rego files
	files, err := filepath.Glob(filepath.Join(dirPath, "*.rego"))
	if err != nil {
		return fmt.Errorf("failed to list policy files: %w", err)
	}

	// Also check subdirectories
	subDirs := []string{"aws", "azure", "gcp", "general"}
	for _, subDir := range subDirs {
		subFiles, err := filepath.Glob(filepath.Join(dirPath, subDir, "*.rego"))
		if err == nil {
			files = append(files, subFiles...)
		}
	}

	if len(files) == 0 {
		return fmt.Errorf("no policy files found in %s", dirPath)
	}

	// Load each policy
	for _, file := range files {
		if err := e.LoadPolicy(ctx, file); err != nil {
			return fmt.Errorf("failed to load policy %s: %w", file, err)
		}
	}

	return nil
}

// GetLoadedPolicies returns the IDs of all loaded policies
func (e *Engine) GetLoadedPolicies() []string {
	policies := make([]string, 0, len(e.policies))
	for id := range e.policies {
		policies = append(policies, id)
	}
	return policies
}

// compile compiles all loaded policies
func (e *Engine) compile() error {
	if len(e.policies) == 0 {
		return fmt.Errorf("no policies to compile")
	}

	modules := make(map[string]*ast.Module)
	for id, policy := range e.policies {
		modules[id] = policy.Module
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return fmt.Errorf("failed to compile policies: %v", compiler.Errors)
	}

	e.compiler = compiler
	return nil
}