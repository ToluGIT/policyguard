package opa

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/ToluGIT/policyguard"
	"github.com/ToluGIT/policyguard/pkg/config"
	"github.com/ToluGIT/policyguard/pkg/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// Engine implements the policy.Engine interface using OPA
type Engine struct {
	compiler       *ast.Compiler
	store          storage.Store
	policies       map[string]*Policy
	severityConfig *config.SeverityConfig
	capabilities   *ast.Capabilities
	// prepared is the deny query prepared once at compile time and reused for
	// every resource. Preparing per-resource (the previous behavior) re-did all
	// query setup on each Eval, making throughput collapse super-linearly on
	// large corpora; preparing once makes per-resource cost just the evaluation.
	prepared *rego.PreparedEvalQuery
}

// restrictedCapabilities returns an OPA capability set that strips every
// non-deterministic built-in function from the default set.
//
// PolicyGuard loads and executes Rego from a user-supplied --policy directory,
// so a policy is untrusted code. The default OPA capabilities expose built-ins
// such as http.send and net.lookup_ip_addr, which would let a malicious policy
// exfiltrate the parsed infrastructure (which may itself contain hardcoded
// credentials from the scanned .tf) to an arbitrary host. A security policy
// must be a pure function of its input.resource; nothing it can legitimately
// need is non-deterministic.
//
// We therefore start from the current OPA version's capabilities and remove
// all built-ins flagged Nondeterministic. In OPA v0.60.0 that is: http.send,
// net.lookup_ip_addr, opa.runtime, io.jwt.encode_sign, io.jwt.encode_sign_raw,
// io.jwt.decode_verify, rand.intn, time.now_ns, and uuid.rfc4122. We key off
// the flag rather than a hardcoded list so a built-in added in a future OPA
// release is stripped automatically. AllowNet is set to an empty slice so the
// type checker cannot fetch remote refs either. A policy that references a
// stripped built-in fails to compile, so the restriction is enforced at load
// time, before any evaluation runs.
func restrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()

	pure := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		if b.Nondeterministic {
			continue
		}
		pure = append(pure, b)
	}
	caps.Builtins = pure

	// Empty (non-nil) means "no host may be connected to" for features that
	// honor AllowNet (e.g. remote JSON Schema refs in the type checker).
	caps.AllowNet = []string{}

	return caps
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
		store:          inmem.New(),
		policies:       make(map[string]*Policy),
		severityConfig: config.NewDefaultSeverityConfig(),
		capabilities:   restrictedCapabilities(),
	}
}

// WithSeverityConfig sets a custom severity configuration
func (e *Engine) WithSeverityConfig(configPath string) error {
	var err error
	e.severityConfig, err = config.LoadSeverityConfig(configPath)
	return err
}

// Evaluate evaluates resources against loaded policies
func (e *Engine) Evaluate(ctx context.Context, resources []types.Resource) (*types.PolicyResult, error) {
	if e.compiler == nil {
		return nil, fmt.Errorf("no policies loaded")
	}

	violations := []types.PolicyViolation{}

	// Build the sibling context exposed to policies as input.all_resources. Only
	// "configuration" resources that another resource can reference as a sibling
	// belong here (e.g. aws_s3_bucket_server_side_encryption_configuration). The
	// vast majority of resources (the primary aws_s3_bucket, EC2 instances, etc.)
	// are never looked up as siblings, so including them would bloat the input
	// passed into every per-resource Eval — that turned evaluation quadratic on
	// large corpora. Filtering to sibling-relevant types keeps this slice small
	// and roughly constant, restoring near-linear scaling.
	allResources := make([]map[string]interface{}, 0)
	for _, r := range resources {
		if !isSiblingResourceType(r.Type) {
			continue
		}
		allResources = append(allResources, map[string]interface{}{
			"id":         r.ID,
			"type":       r.Type,
			"name":       r.Name,
			"attributes": r.Attributes,
		})
	}

	// Evaluate each resource against all policies
	for _, resource := range resources {
		resourceViolations, err := e.evaluateResource(ctx, resource, allResources)
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

// siblingResourceTypes are the resource types that policies look up as siblings
// of another resource (via input.all_resources). Keep this in sync with the
// policies that perform sibling matching — today, the S3 split-resource
// configuration resources. Resources not listed here are never referenced as a
// sibling, so excluding them from input.all_resources is safe and keeps the
// per-evaluation input small.
var siblingResourceTypes = map[string]bool{
	"aws_s3_bucket_server_side_encryption_configuration": true,
	"aws_s3_bucket_logging":                              true,
}

func isSiblingResourceType(t string) bool {
	return siblingResourceTypes[t]
}

// evaluateResource evaluates a single resource against all policies. allResources
// is the compact view of every parsed resource, exposed to policies as
// input.all_resources so they can reason about related/sibling resources without
// changing the input.resource contract the existing single-resource policies use.
func (e *Engine) evaluateResource(ctx context.Context, resource types.Resource, allResources []map[string]interface{}) ([]types.PolicyViolation, error) {
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
		"all_resources": allResources,
	}

	if e.prepared == nil {
		return nil, fmt.Errorf("query not prepared")
	}

	// Evaluate using the query prepared once at compile time, passing only the
	// per-resource input here. This avoids re-preparing the query for every
	// resource (the cause of the previous super-linear slowdown).
	rs, err := e.prepared.Eval(ctx, rego.EvalInput(input))
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

	var policyID string
	if pid, ok := vMap["policy_id"].(string); ok {
		policyID = pid
		violation.PolicyID = pid
	}

	// Get the original severity from the policy
	var originalSeverity string
	if sev, ok := vMap["severity"].(string); ok {
		originalSeverity = sev
	}

	// Apply severity customization if we have both policy ID and original severity
	if policyID != "" && e.severityConfig != nil {
		customSeverity := e.severityConfig.GetSeverity(policyID, originalSeverity)
		violation.Severity = customSeverity
	} else if originalSeverity != "" {
		// Use original severity if no customization or missing policy ID
		violation.Severity = originalSeverity
	} else {
		// Fallback to medium severity if nothing else works
		violation.Severity = types.SeverityMedium
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
	// Check if directory exists
	if _, err := ioutil.ReadDir(dirPath); err != nil {
		// Directory doesn't exist, try embedded policies
		if policyguard.HasEmbeddedPolicies() {
			return e.LoadEmbeddedPolicies(ctx)
		}
		return fmt.Errorf("policy directory not found and no embedded policies available: %w", err)
	}

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
		// No files found in directory, try embedded policies
		if policyguard.HasEmbeddedPolicies() {
			return e.LoadEmbeddedPolicies(ctx)
		}
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

// LoadEmbeddedPolicies loads policies from embedded filesystem
func (e *Engine) LoadEmbeddedPolicies(ctx context.Context) error {
	embeddedPolicies, err := policyguard.GetEmbeddedPolicies()
	if err != nil {
		return fmt.Errorf("failed to get embedded policies: %w", err)
	}

	if len(embeddedPolicies) == 0 {
		return fmt.Errorf("no embedded policies found")
	}

	// Load each embedded policy
	for path, content := range embeddedPolicies {
		// Parse the module
		module, err := ast.ParseModule(path, content)
		if err != nil {
			return fmt.Errorf("failed to parse embedded policy %s: %w", path, err)
		}

		// Extract policy ID from path
		policyID := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		// Store the policy
		e.policies[policyID] = &Policy{
			ID:     policyID,
			Module: module,
		}
	}

	// Compile all policies
	return e.compile()
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

	// Compile with the restricted capability set so any policy that references a
	// non-deterministic built-in (e.g. http.send) is rejected at load time.
	compiler := ast.NewCompiler().WithCapabilities(e.capabilities)
	compiler.Compile(modules)
	if compiler.Failed() {
		return fmt.Errorf("failed to compile policies: %v", compiler.Errors)
	}

	e.compiler = compiler

	// Prepare the deny query once against the freshly compiled policies. The same
	// capability sandbox is applied here so a stripped built-in is still rejected.
	// The prepared query is reused for every resource in Evaluate.
	pq, err := rego.New(
		rego.Query("data.policyguard.deny[x]"),
		rego.Compiler(compiler),
		rego.Store(e.store),
		rego.Capabilities(e.capabilities),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("failed to prepare query: %w", err)
	}
	e.prepared = &pq

	return nil
}
