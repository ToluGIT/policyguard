package terraform

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/ToluGIT/policyguard/pkg/logger"
	"github.com/ToluGIT/policyguard/pkg/types"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Parser implements the parser.Parser interface for Terraform files
type Parser struct {
	parser     *hclparse.Parser
	variables  map[string]cty.Value      // Store extracted variables
	functions  map[string]function.Function // Standard Terraform functions
	evalContext *hcl.EvalContext       // Evaluation context for variables and functions
	log       *logger.Logger          // Logger for debug output
}

// New creates a new Terraform parser
func New() *Parser {
	// Create a new parser with empty variable map and evaluation context
	p := &Parser{
		parser:    hclparse.NewParser(),
		variables: make(map[string]cty.Value),
		functions: make(map[string]function.Function),
		evalContext: &hcl.EvalContext{
			Variables: make(map[string]cty.Value),
			Functions: make(map[string]function.Function),
		},
		log: logger.Default(),
	}
	
	// Initialize the evaluation context
	p.initEvalContext()
	
	return p
}

// WithLogger sets a custom logger for the parser
func (p *Parser) WithLogger(log *logger.Logger) *Parser {
	p.log = log
	return p
}

// TerraformVariable represents a Terraform variable declaration
type TerraformVariable struct {
	Name        string
	Type        string
	Description string
	Default     cty.Value
	Required    bool
}

// initEvalContext initializes the evaluation context with standard functions
func (p *Parser) initEvalContext() {
	// Initialize standard Terraform functions (minimal set for now)
	// TODO: Add more standard Terraform functions as needed
	
	// Update the evaluation context
	p.evalContext.Variables = p.variables
	p.evalContext.Functions = p.functions
}

// Parse parses a single Terraform or OpenTofu file
func (p *Parser) Parse(ctx context.Context, filePath string) ([]types.Resource, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var file *hcl.File
	var diags hcl.Diagnostics

	// Check for JSON extensions first (.tf.json or .tofu.json)
	if strings.HasSuffix(filePath, ".tf.json") || strings.HasSuffix(filePath, ".tofu.json") {
		file, diags = p.parser.ParseJSON(content, filePath)
	} else if strings.HasSuffix(filePath, ".tf") || strings.HasSuffix(filePath, ".tofu") {
		file, diags = p.parser.ParseHCL(content, filePath)
	} else {
		return nil, fmt.Errorf("unsupported file extension: %s", filepath.Ext(filePath))
	}

	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse file: %s", diags.Error())
	}
	
	// If this is a variables.tf file, extract variables first
	if strings.Contains(filepath.Base(filePath), "variables") {
		err = p.extractVariablesFromFile(file, filePath)
		if err != nil {
			// Log warning but continue with parsing
			p.log.Warn("Error extracting variables from %s: %v", filePath, err)
		}
		// Update evaluation context
		p.updateEvalContext()
	}

	return p.extractResources(file, filePath)
}

// ParseDirectory parses all Terraform and OpenTofu files in a directory
func (p *Parser) ParseDirectory(ctx context.Context, dirPath string) ([]types.Resource, error) {
	// Reset the variable map for this directory
	p.variables = make(map[string]cty.Value)
	p.evalContext.Variables = p.variables
	
	// Collect all supported file patterns
	patterns := []string{
		"*.tf",
		"*.tf.json",
		"*.tofu",
		"*.tofu.json",
	}

	var allFiles []string
	for _, pattern := range patterns {
		files, err := filepath.Glob(filepath.Join(dirPath, pattern))
		if err != nil {
			return nil, fmt.Errorf("failed to list %s files: %w", pattern, err)
		}
		allFiles = append(allFiles, files...)
	}

	// First pass: extract variables from all files
	err := p.extractVariables(ctx, allFiles)
	if err != nil {
		// Log warning but continue with parsing
		p.log.Warn("Error extracting variables: %v", err)
	}
	
	var allResources []types.Resource
	var moduleResources []types.Resource
	
	// Second pass: extract all resources and identify modules (with variable resolution)
	for _, file := range allFiles {
		resources, err := p.Parse(ctx, file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}
		
		for _, resource := range resources {
			if resource.Type == "module" {
				moduleResources = append(moduleResources, resource)
				// Also add the module resource itself to allResources
				allResources = append(allResources, resource)
			} else {
				allResources = append(allResources, resource)
			}
		}
	}
	
	// Third pass: process modules and extract their resources
	resolvedModuleResources, err := p.resolveModules(ctx, moduleResources, dirPath)
	if err != nil {
		// Log the error but don't fail the entire parsing
		p.log.Warn("Error resolving modules: %v", err)
	}
	
	// Add resolved module resources to the result
	allResources = append(allResources, resolvedModuleResources...)
	
	return allResources, nil
}

// extractVariables extracts variable declarations from all files in a directory
func (p *Parser) extractVariables(ctx context.Context, files []string) error {
	for _, file := range files {
		// Skip files that don't contain variable declarations
		// This is an optimization to avoid parsing all files
		if !isLikelyToContainVariables(file) {
			continue
		}
		
		content, err := ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file, err)
		}
		
		var hclFile *hcl.File
		var diags hcl.Diagnostics
		
		// Parse the file based on its extension
		if strings.HasSuffix(file, ".tf.json") || strings.HasSuffix(file, ".tofu.json") {
			hclFile, diags = p.parser.ParseJSON(content, file)
		} else if strings.HasSuffix(file, ".tf") || strings.HasSuffix(file, ".tofu") {
			hclFile, diags = p.parser.ParseHCL(content, file)
		} else {
			continue // Skip unsupported files
		}
		
		if diags.HasErrors() {
			return fmt.Errorf("failed to parse file for variables: %s", diags.Error())
		}
		
		// Extract variables from the file
		err = p.extractVariablesFromFile(hclFile, file)
		if err != nil {
			return fmt.Errorf("failed to extract variables from %s: %w", file, err)
		}
	}
	
	// Update the evaluation context with the extracted variables
	p.updateEvalContext()
	
	return nil
}

// isLikelyToContainVariables does a quick check if the file might contain variable declarations
// This is an optimization to avoid parsing all files for variables
func isLikelyToContainVariables(filePath string) bool {
	// Common patterns for files containing variables
	patterns := []string{
		"variables.tf",
		"vars.tf",
		"inputs.tf",
	}
	
	fileName := filepath.Base(filePath)
	
	// Check against common variable file patterns
	for _, pattern := range patterns {
		if strings.Contains(fileName, pattern) {
			return true
		}
	}
	
	// Check if it's a Terraform/OpenTofu file (might still contain variable declarations)
	return strings.HasSuffix(filePath, ".tf") || strings.HasSuffix(filePath, ".tofu")
}

// extractVariablesFromFile extracts variable declarations from an HCL file
func (p *Parser) extractVariablesFromFile(file *hcl.File, filePath string) error {
	// Extract variable blocks from HCL syntax files (.tf, .tofu)
	if body, ok := file.Body.(*hclsyntax.Body); ok {
		for _, block := range body.Blocks {
			if block.Type == "variable" && len(block.Labels) > 0 {
				varName := block.Labels[0]
				varValue, err := p.extractVariableFromHCLBlock(block)
				if err != nil {
					// Log and continue
					p.log.Warn("Failed to extract variable %s: %v", varName, err)
					continue
				}
				
				// Store the variable
				p.variables[varName] = varValue
			}
		}
		return nil
	}
	
	// Extract variables from JSON files (.tf.json, .tofu.json)
	content, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "variable", LabelNames: []string{"name"}},
		},
	})
	
	if diags.HasErrors() {
		return fmt.Errorf("failed to parse content for variables: %s", diags.Error())
	}
	
	for _, block := range content.Blocks {
		if block.Type == "variable" && len(block.Labels) > 0 {
			varName := block.Labels[0]
			varValue, err := p.extractVariableFromJSONBlock(block)
			if err != nil {
				// Log and continue
				p.log.Warn("Failed to extract variable %s from JSON: %v", varName, err)
				continue
			}
			
			// Store the variable
			p.variables[varName] = varValue
		}
	}
	
	return nil
}

// extractVariableFromHCLBlock extracts variable information from an HCL block
func (p *Parser) extractVariableFromHCLBlock(block *hclsyntax.Block) (cty.Value, error) {
	// Default to unknown value
	result := cty.DynamicVal
	
	// Check for default value attribute
	if defaultAttr, ok := block.Body.Attributes["default"]; ok {
		val, diags := defaultAttr.Expr.Value(nil)
		if !diags.HasErrors() {
			result = val
		}
	}
	
	return result, nil
}

// extractVariableFromJSONBlock extracts variable information from a JSON block
func (p *Parser) extractVariableFromJSONBlock(block *hcl.Block) (cty.Value, error) {
	// Default to unknown value
	result := cty.DynamicVal
	
	// Extract attributes from the block body
	attrs, diags := block.Body.JustAttributes()
	if diags.HasErrors() {
		return result, fmt.Errorf("failed to extract variable attributes: %s", diags.Error())
	}
	
	// Check for default value attribute
	if defaultAttr, ok := attrs["default"]; ok {
		val, diags := defaultAttr.Expr.Value(nil)
		if !diags.HasErrors() {
			result = val
		}
	}
	
	return result, nil
}

// updateEvalContext updates the evaluation context with current variables
func (p *Parser) updateEvalContext() {
	// Create the variables map structure for HCL evaluation
	vars := make(map[string]cty.Value)
	
	// Add var namespace for variable references
	varMap := make(map[string]cty.Value)
	for k, v := range p.variables {
		varMap[k] = v
		
		// No debug output for extracted variables - disabled to prevent verbosity
	}
	
	// Only create the object if we have variables
	if len(varMap) > 0 {
		// Try to create the object value
		objectVal, err := cty.ObjectVal(varMap), error(nil)
		if err != nil {
			p.log.Warn("Error creating variable object: %v", err)
			// Individual variables will not be accessible via var.name
		} else {
			vars["var"] = objectVal
		}
	}
	
	// Update the evaluation context
	p.evalContext.Variables = vars
}

// resolveModules attempts to resolve and parse resources from module sources
func (p *Parser) resolveModules(ctx context.Context, modules []types.Resource, basePath string) ([]types.Resource, error) {
	var moduleResources []types.Resource
	
	for _, module := range modules {
		// Get module source path
		source, ok := module.Attributes["source"].(string)
		if !ok || source == "" {
			// Skip modules without a valid source
			p.log.Warn("Module %s has no source attribute, skipping", module.Name)
			continue
		}
		
		// Extract module variables from attributes
		moduleVars := make(map[string]interface{})
		securityCriticalVars := make(map[string]interface{})
		
		// First pass: collect all module variables
		for key, val := range module.Attributes {
			if key != "source" && !strings.HasPrefix(key, "_") {
				moduleVars[key] = val
			}
		}
		
		// Second pass: identify security-critical variables and create markers
		for key, val := range moduleVars {
			// Track security-critical variables separately for direct propagation
			if p.isSecurityCriticalVariable(key, val) {
				securityCriticalVars[key] = val
				p.log.Debug("Found security-critical variable %s in module %s", key, module.Name)
				
				// Process conditional expressions specially
				if condMap, isCond := val.(map[string]interface{}); isCond && 
				   condMap["_type"] == "conditional_expression" {
					
					// Get the security value for conditional expressions
					if secVal, hasSec := condMap["_security_value"]; hasSec {
						// Special handling based on variable name and value
						switch key {
						case "publicly_accessible":
							if bVal, isBool := secVal.(bool); isBool && bVal {
								securityCriticalVars["_security_publicly_accessible"] = true
								p.log.Debug("Found insecure conditional value for publicly_accessible in module %s", module.Name)
							}
						case "storage_encrypted":
							if bVal, isBool := secVal.(bool); isBool && !bVal {
								securityCriticalVars["_security_unencrypted"] = true
								p.log.Debug("Found insecure conditional value for storage_encrypted in module %s", module.Name)
							}
						case "iam_database_authentication_enabled":
							if bVal, isBool := secVal.(bool); isBool && !bVal {
								securityCriticalVars["_security_no_iam_auth"] = true
							}
						case "deletion_protection":
							if bVal, isBool := secVal.(bool); isBool && !bVal {
								securityCriticalVars["_security_no_deletion_protection"] = true
							}
						case "backup_retention_period":
							if numVal, isNum := secVal.(float64); isNum && numVal == 0 {
								securityCriticalVars["_security_no_backup"] = true
							}
						}
					}
					continue // Already handled conditional expression
				}
				
				// For explicit boolean security settings, pre-process for policy detection
				if boolVal, isBool := val.(bool); isBool {
					switch key {
					case "publicly_accessible":
						if boolVal { // true is insecure
							securityCriticalVars["_security_publicly_accessible"] = true
							p.log.Debug("Found publicly_accessible=true in module %s", module.Name)
						}
					case "storage_encrypted":
						if !boolVal { // false is insecure
							securityCriticalVars["_security_unencrypted"] = true
							p.log.Debug("Found storage_encrypted=false in module %s", module.Name)
						}
					case "iam_database_authentication_enabled":
						if !boolVal { // false is insecure
							securityCriticalVars["_security_no_iam_auth"] = true
							p.log.Debug("Found iam_database_authentication_enabled=false in module %s", module.Name)
						}
					case "deletion_protection":
						if !boolVal { // false is insecure
							securityCriticalVars["_security_no_deletion_protection"] = true
							p.log.Debug("Found deletion_protection=false in module %s", module.Name)
						}
					}
				}
				
				// Handle numeric values like backup_retention_period
				if numVal, isNum := val.(float64); isNum {
					if key == "backup_retention_period" && numVal == 0 {
						securityCriticalVars["_security_no_backup"] = true
						p.log.Debug("Found backup_retention_period=0 in module %s", module.Name)
					}
				}
				
				// Handle slices like enabled_cloudwatch_logs_exports
				if arr, isArr := val.([]interface{}); isArr {
					if key == "enabled_cloudwatch_logs_exports" && len(arr) == 0 {
						securityCriticalVars["_security_no_log_exports"] = true
						p.log.Debug("Found empty enabled_cloudwatch_logs_exports in module %s", module.Name)
					}
				}
				
				// Handle variable references
				if varRef, isStr := val.(string); isStr && strings.HasPrefix(varRef, "[var.") {
					varName := strings.TrimPrefix(strings.TrimSuffix(varRef, "]"), "[var.")
					p.log.Debug("Found variable reference %s in module variable %s", varName, key)
					
					// Handle common patterns for conditional security variables
					if key == "publicly_accessible" && strings.Contains(varRef, "!var.") {
						// Likely a negated boolean variable like !var.production_mode which is insecure
						securityCriticalVars["_security_publicly_accessible"] = true
						p.log.Debug("Detected likely insecure pattern: negated variable for publicly_accessible in module %s", module.Name)
					} else if key == "storage_encrypted" && strings.Contains(varRef, "var.") {
						// Assume a variable without negation is potentially insecure for storage_encrypted
						securityCriticalVars["_security_unencrypted"] = true
						p.log.Debug("Detected potentially insecure pattern: variable reference for storage_encrypted in module %s", module.Name)
					}
				}
			}
		}
		
		// Log module parsing information
		p.log.Debug("Processing module %s with source %s", module.Name, source)
		p.log.Debug("Module %s has %d security markers", module.Name, len(securityCriticalVars))
		
		// Handle local modules (starting with ./ or ../)
		if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			// Resolve relative path
			modulePath := filepath.Join(basePath, source)
			
			// Check if the path exists
			if _, err := os.Stat(modulePath); os.IsNotExist(err) {
				// Module path doesn't exist, log and skip
				p.log.Warn("Module path does not exist: %s", modulePath)
				continue
			}
			
			p.log.Debug("Found module at path: %s", modulePath)
			
			// Create a special security map to pass to the module parser
			// that contains BOTH the original variables and the enhanced security markers
			enhancedSecurityVars := make(map[string]interface{})
			
			// Copy all security-critical variables
			for k, v := range securityCriticalVars {
				enhancedSecurityVars[k] = v
			}
			
			// Copy security-relevant original variables as well
			for k, v := range moduleVars {
				if p.isSecurityCriticalVariable(k, v) {
					enhancedSecurityVars[k] = v
				}
			}
			
			// Parse module directory with variables and pre-processed security attributes
			resources, err := p.ParseModuleWithVars(ctx, modulePath, module.Name, moduleVars, enhancedSecurityVars)
			if err != nil {
				// Log the error but continue with other modules
				p.log.Warn("Failed to parse module %s: %v", module.Name, err)
				continue
			}
			
			// Log the detected security issues
			for marker, _ := range securityCriticalVars {
				if strings.HasPrefix(marker, "_security_") {
					p.log.Debug("Module %s has security marker: %s", module.Name, marker)
				}
			}
			
			moduleResources = append(moduleResources, resources...)
			p.log.Debug("Parsed %d resources from module %s", len(resources), module.Name)
		} else {
			// For non-local modules (remote registry, git, etc.), we'd need to download them first
			// For now, we'll just log that we can't handle them yet
			p.log.Debug("Note: Skipping remote module %s with source %s", module.Name, source)
		}
	}
	
	return moduleResources, nil
}

// ParseModuleWithVars parses a module directory with parent variables and module variables
func (p *Parser) ParseModuleWithVars(ctx context.Context, modulePath, moduleName string, moduleVars map[string]interface{}, precalculatedSecurityVars ...map[string]interface{}) ([]types.Resource, error) {
	// Create a new parser with combined variables
	moduleParser := New()
	
	// Copy parent variables to the module parser
	for k, v := range p.variables {
		moduleParser.variables[k] = v
	}
	
	// Track security-critical variables for enhanced analysis
	securityCriticalVars := make(map[string]interface{})
	
	// If precalculated security variables were provided, use them
	// This allows the caller to preprocess security markers based on module inputs
	if len(precalculatedSecurityVars) > 0 && precalculatedSecurityVars[0] != nil {
		for k, v := range precalculatedSecurityVars[0] {
			securityCriticalVars[k] = v
			if strings.HasPrefix(k, "_security_") {
				p.log.Debug("Using precalculated security marker %s = %v for module %s", k, v, moduleName)
			}
		}
	}
	
	// Add module-specific variables
	for k, v := range moduleVars {
		// Convert to cty.Value for Terraform evaluation
		ctyVal, err := p.convertToCtyValue(v)
		if err == nil {
			moduleParser.variables[k] = ctyVal
		}
		
		// Process security-critical variables specially if not already processed
		if p.isSecurityCriticalVariable(k, v) && len(precalculatedSecurityVars) == 0 {
			securityCriticalVars[k] = v
			
			// For boolean security settings, retain the worst-case scenario for security analysis
			if condMap, ok := v.(map[string]interface{}); ok && condMap["_type"] == "conditional_expression" {
				if secVal, ok := condMap["_security_value"]; ok {
					securityCriticalVars[k+"_security_value"] = secVal
				}
			}
		}
	}
	
	// Update the evaluation context
	moduleParser.updateEvalContext()
	
	// Parse module directory
	p.log.Debug("Parsing module at %s with %d security critical vars", modulePath, len(securityCriticalVars))
	resources, err := moduleParser.ParseDirectory(ctx, modulePath)
	
	// Handle parsing error
	if err != nil {
		return nil, err
	}
	
	p.log.Debug("Found %d resources in module %s", len(resources), moduleName)
	
	// Add module context to resources
	for i := range resources {
		// Skip module resources to avoid infinite recursion
		if resources[i].Type == "module" {
			continue
		}
		
		// Update resource ID to include module prefix
		resources[i].ID = fmt.Sprintf("module.%s.%s", moduleName, resources[i].ID)
		
		// Add module information to attributes
		if resources[i].Attributes == nil {
			resources[i].Attributes = make(map[string]interface{})
		}
		resources[i].Attributes["_module_name"] = moduleName
		resources[i].Attributes["_module_path"] = modulePath
		
		// Add a copy of module variables for security context
		moduleVarsCopy := make(map[string]interface{})
		for k, v := range moduleVars {
			moduleVarsCopy[k] = v
		}
		resources[i].Attributes["_module_vars"] = moduleVarsCopy
		
		// Add enhanced security context
		resources[i].Attributes["_security_critical_vars"] = securityCriticalVars
		
		// Important: Add the security markers directly to the RDS resources
		if strings.HasPrefix(resources[i].Type, "aws_db_instance") || 
		   strings.HasPrefix(resources[i].Type, "aws_rds_cluster") {
			// Log that we found an RDS resource in the module
			p.log.Debug("Found RDS resource %s in module %s", resources[i].ID, moduleName)
			
			// Add all security markers directly to the resource attributes for policy detection
			for k, v := range securityCriticalVars {
				if strings.HasPrefix(k, "_security_") {
					resources[i].Attributes[k] = v
					p.log.Debug("Adding security marker %s = %v to RDS resource %s", k, v, resources[i].ID)
				}
			}
			
			// Make sure critical security variables are directly accessible to OPA policies
			// by explicitly adding special markers based on module inputs
			if val, exists := moduleVars["publicly_accessible"]; exists {
				if boolVal, isBool := val.(bool); isBool && boolVal == true {
					resources[i].Attributes["_security_publicly_accessible"] = true
					p.log.Debug("Direct security marker: _security_publicly_accessible = true for %s", resources[i].ID)
				}
			}
			
			if val, exists := moduleVars["storage_encrypted"]; exists {
				if boolVal, isBool := val.(bool); isBool && boolVal == false {
					resources[i].Attributes["_security_unencrypted"] = true
					p.log.Debug("Direct security marker: _security_unencrypted = true for %s", resources[i].ID)
				}
			}
			
			if val, exists := moduleVars["backup_retention_period"]; exists {
				if numVal, isNum := val.(float64); isNum && numVal == 0 {
					resources[i].Attributes["_security_no_backup"] = true
					p.log.Debug("Direct security marker: _security_no_backup = true for %s", resources[i].ID)
				}
			}
			
			if val, exists := moduleVars["iam_database_authentication_enabled"]; exists {
				if boolVal, isBool := val.(bool); isBool && boolVal == false {
					resources[i].Attributes["_security_no_iam_auth"] = true
					p.log.Debug("Direct security marker: _security_no_iam_auth = true for %s", resources[i].ID)
				}
			}
			
			if val, exists := moduleVars["deletion_protection"]; exists {
				if boolVal, isBool := val.(bool); isBool && boolVal == false {
					resources[i].Attributes["_security_no_deletion_protection"] = true
					p.log.Debug("Direct security marker: _security_no_deletion_protection = true for %s", resources[i].ID)
				}
			}
			
			if val, exists := moduleVars["enabled_cloudwatch_logs_exports"]; exists {
				if arr, isArr := val.([]interface{}); isArr && len(arr) == 0 {
					resources[i].Attributes["_security_no_log_exports"] = true
					p.log.Debug("Direct security marker: _security_no_log_exports = true for %s", resources[i].ID)
				}
			}
		} else {
			// For non-RDS resources, still add security markers but they won't be used in policies
			for k, v := range securityCriticalVars {
				if strings.HasPrefix(k, "_security_") {
					resources[i].Attributes[k] = v
				}
			}
		}
		
		// Apply enhanced variable resolution for security-critical attributes
		p.enhanceSecurityAttributesFromModuleVars(resources[i], moduleVars)
	}
	
	return resources, nil
}

// Helper to convert Go values to cty values
func (p *Parser) convertToCtyValue(value interface{}) (cty.Value, error) {
	switch v := value.(type) {
	case nil:
		return cty.NullVal(cty.DynamicPseudoType), nil
	case bool:
		return cty.BoolVal(v), nil
	case int:
		return cty.NumberIntVal(int64(v)), nil
	case int64:
		return cty.NumberIntVal(v), nil
	case float64:
		return cty.NumberFloatVal(v), nil
	case string:
		// Handle special string patterns
		if strings.Contains(v, "[CONDITIONAL:") || strings.Contains(v, "[VARIABLE_REFERENCE]") {
			return cty.DynamicVal, nil
		}
		return cty.StringVal(v), nil
	case []interface{}:
		vals := make([]cty.Value, len(v))
		for i, elem := range v {
			val, err := p.convertToCtyValue(elem)
			if err != nil {
				return cty.DynamicVal, err
			}
			vals[i] = val
		}
		return cty.TupleVal(vals), nil
	case map[string]interface{}:
		// Check for special conditional format
		if typeVal, ok := v["_type"]; ok && typeVal == "conditional_expression" {
			// For security analysis, use the security value
			if secVal, ok := v["_security_value"]; ok {
				return p.convertToCtyValue(secVal)
			}
			// If no security value, try the string representation
			if strVal, ok := v["_string_value"]; ok {
				return p.convertToCtyValue(strVal)
			}
			return cty.DynamicVal, nil
		}
		
		// Regular map
		vals := make(map[string]cty.Value)
		for k, elem := range v {
			val, err := p.convertToCtyValue(elem)
			if err != nil {
				return cty.DynamicVal, err
			}
			vals[k] = val
		}
		return cty.ObjectVal(vals), nil
	default:
		return cty.DynamicVal, fmt.Errorf("unsupported type: %T", value)
	}
}

// ParseModuleDirectory parses a module directory and adds module context to resources
func (p *Parser) ParseModuleDirectory(ctx context.Context, modulePath string, moduleName string) ([]types.Resource, error) {
	// For backward compatibility, call ParseModuleWithVars with empty vars
	return p.ParseModuleWithVars(ctx, modulePath, moduleName, make(map[string]interface{}))
}

// SupportedExtensions returns the file extensions this parser supports
func (p *Parser) SupportedExtensions() []string {
	return []string{".tf", ".tf.json", ".tofu", ".tofu.json"}
}

// extractResources extracts resources from the parsed HCL file
func (p *Parser) extractResources(file *hcl.File, filePath string) ([]types.Resource, error) {
	var resources []types.Resource

	// Handle HCL syntax files (.tf, .tofu)
	if body, ok := file.Body.(*hclsyntax.Body); ok {
		for _, block := range body.Blocks {
			switch block.Type {
			case "resource":
				resource, err := p.extractResource(block, filePath)
				if err != nil {
					return nil, err
				}
				resources = append(resources, *resource)
			case "data":
				// Handle data sources if needed
				resource, err := p.extractDataSource(block, filePath)
				if err != nil {
					return nil, err
				}
				resources = append(resources, *resource)
			case "module":
				// Handle module blocks
				moduleInfo, err := p.extractModuleInfo(block, filePath)
				if err != nil {
					// Log the error but don't fail the entire parsing
					p.log.Warn("Failed to extract module info: %v", err)
					continue
				}
				// Store module info as a special resource type
				resources = append(resources, *moduleInfo)
			}
		}
		return resources, nil
	}

	// Handle JSON files (.tf.json, .tofu.json) - they use the generic HCL body interface
	content, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "resource", LabelNames: []string{"type", "name"}},
			{Type: "data", LabelNames: []string{"type", "name"}},
			{Type: "module", LabelNames: []string{"name"}},
		},
	})
	
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse content: %s", diags.Error())
	}

	for _, block := range content.Blocks {
		switch block.Type {
		case "resource":
			resource, err := p.extractResourceFromJSON(block, filePath)
			if err != nil {
				return nil, err
			}
			resources = append(resources, *resource)
		case "data":
			resource, err := p.extractDataSourceFromJSON(block, filePath)
			if err != nil {
				return nil, err
			}
			resources = append(resources, *resource)
		case "module":
			// Handle module blocks from JSON
			moduleInfo, err := p.extractModuleInfoFromJSON(block, filePath)
			if err != nil {
				// Log the error but don't fail the entire parsing
				p.log.Warn("Failed to extract module info from JSON: %v", err)
				continue
			}
			// Store module info as a special resource type
			resources = append(resources, *moduleInfo)
		}
	}
	
	return resources, nil
}

// extractResource extracts a resource from an HCL block
func (p *Parser) extractResource(block *hclsyntax.Block, filePath string) (*types.Resource, error) {
	if len(block.Labels) < 2 {
		return nil, fmt.Errorf("resource block missing required labels")
	}

	resourceType := block.Labels[0]
	resourceName := block.Labels[1]
	provider := strings.Split(resourceType, "_")[0]

	attributes := make(map[string]interface{})
	
	// Extract attributes
	for name, attr := range block.Body.Attributes {
		val, err := p.extractAttributeValue(attr)
		if err != nil {
			// Skip attributes we can't parse
			continue
		}
		attributes[name] = val
	}

	// Extract nested blocks
	blocksByType := make(map[string][]map[string]interface{})
	for _, nestedBlock := range block.Body.Blocks {
		nestedAttrs, err := p.extractNestedBlock(nestedBlock)
		if err != nil {
			continue
		}
		blocksByType[nestedBlock.Type] = append(blocksByType[nestedBlock.Type], nestedAttrs)
	}
	
	// Add blocks to attributes - certain types should always be arrays
	for blockType, blocks := range blocksByType {
		// Always use arrays for ingress/egress rules and similar repeatable blocks
		if blockType == "ingress" || blockType == "egress" || blockType == "rule" {
			attributes[blockType] = blocks
		} else if len(blocks) == 1 {
			attributes[blockType] = blocks[0]
		} else {
			attributes[blockType] = blocks
		}
	}

	location := types.Location{
		File:   filePath,
		Line:   block.TypeRange.Start.Line,
		Column: block.TypeRange.Start.Column,
	}

	return &types.Resource{
		ID:         fmt.Sprintf("%s.%s", resourceType, resourceName),
		Type:       resourceType,
		Provider:   provider,
		Name:       resourceName,
		Attributes: attributes,
		Location:   location,
	}, nil
}

// extractDataSource extracts a data source from an HCL block
func (p *Parser) extractDataSource(block *hclsyntax.Block, filePath string) (*types.Resource, error) {
	if len(block.Labels) < 2 {
		return nil, fmt.Errorf("data block missing required labels")
	}

	dataType := block.Labels[0]
	dataName := block.Labels[1]
	provider := strings.Split(dataType, "_")[0]

	attributes := make(map[string]interface{})
	
	// Extract attributes
	for name, attr := range block.Body.Attributes {
		val, err := p.extractAttributeValue(attr)
		if err != nil {
			continue
		}
		attributes[name] = val
	}
	
	// Extract nested blocks for data sources too
	blocksByType := make(map[string][]map[string]interface{})
	for _, nestedBlock := range block.Body.Blocks {
		nestedAttrs, err := p.extractNestedBlock(nestedBlock)
		if err != nil {
			continue
		}
		blocksByType[nestedBlock.Type] = append(blocksByType[nestedBlock.Type], nestedAttrs)
	}
	
	// Add blocks to attributes - single blocks as objects, multiple as arrays
	for blockType, blocks := range blocksByType {
		if len(blocks) == 1 {
			attributes[blockType] = blocks[0]
		} else {
			attributes[blockType] = blocks
		}
	}

	location := types.Location{
		File:   filePath,
		Line:   block.TypeRange.Start.Line,
		Column: block.TypeRange.Start.Column,
	}

	return &types.Resource{
		ID:         fmt.Sprintf("data.%s.%s", dataType, dataName),
		Type:       fmt.Sprintf("data.%s", dataType),
		Provider:   provider,
		Name:       dataName,
		Attributes: attributes,
		Location:   location,
	}, nil
}

// extractNestedBlock extracts attributes from a nested block
func (p *Parser) extractNestedBlock(block *hclsyntax.Block) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	
	// Check if this is a dynamic block
	if block.Type == "dynamic" && len(block.Labels) > 0 {
		// Extract the dynamic block type (e.g., "server_side_encryption_configuration")
		dynamicBlockType := block.Labels[0]
		result["_is_dynamic"] = true
		result["_dynamic_type"] = dynamicBlockType
		
		// Extract for_each condition
		forEachAttr, hasForEach := block.Body.Attributes["for_each"]
		if hasForEach {
			// Try to evaluate the condition
			forEachVal, err := p.extractAttributeValue(forEachAttr)
			if err == nil {
				result["_for_each"] = forEachVal
			}
			
			// Check for conditional expressions in for_each
			if conditional, ok := forEachAttr.Expr.(*hclsyntax.ConditionalExpr); ok {
				result["_conditional_for_each"] = true
				
				// Extract both possible values
				trueBranch, _ := p.extractGenericExpression(conditional.TrueResult)
				falseBranch, _ := p.extractGenericExpression(conditional.FalseResult)
				
				result["_true_branch"] = trueBranch
				result["_false_branch"] = falseBranch
				
				// Try to extract the condition itself
				condition, _ := p.extractGenericExpression(conditional.Condition)
				result["_condition"] = condition
			}
		}
		
		// Extract the content template for security analysis
		// even if condition currently evaluates to false
		for _, contentBlock := range block.Body.Blocks {
			if contentBlock.Type == "content" {
				contentAttrs, _ := p.extractNestedBlock(contentBlock)
				result["_content"] = contentAttrs
				break
			}
		}
		
		return result, nil
	}
	
	// Extract attributes
	for name, attr := range block.Body.Attributes {
		val, err := p.extractAttributeValue(attr)
		if err != nil {
			continue
		}
		result[name] = val
	}

	// Handle nested blocks recursively
	for _, nestedBlock := range block.Body.Blocks {
		nestedAttrs, err := p.extractNestedBlock(nestedBlock)
		if err != nil {
			continue
		}
		result[nestedBlock.Type] = nestedAttrs
	}

	return result, nil
}

// extractAttributeValue extracts the value from an HCL attribute
func (p *Parser) extractAttributeValue(attr *hclsyntax.Attribute) (interface{}, error) {
	// First try evaluation with the variable context
	val, diags := attr.Expr.Value(p.evalContext)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// If evaluation with context fails, try direct evaluation
	val, diags = attr.Expr.Value(nil)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}

	// If direct evaluation fails, check for different expression types
	
	// Check if it's a function call
	if funcCall, ok := attr.Expr.(*hclsyntax.FunctionCallExpr); ok {
		return p.extractFunctionCall(funcCall)
	}
	
	// Check if it's a variable reference and try to handle it specially
	if varRef, ok := attr.Expr.(*hclsyntax.ScopeTraversalExpr); ok {
		return p.extractVariableReference(varRef)
	}
	
	// Check if it's a template expression (string interpolation)
	if tmpl, ok := attr.Expr.(*hclsyntax.TemplateExpr); ok {
		return p.extractTemplateExpression(tmpl)
	}
	
	// Check if it's a conditional expression
	if conditional, ok := attr.Expr.(*hclsyntax.ConditionalExpr); ok {
		return p.extractConditionalExpression(conditional)
	}
	
	// Check if it's an operation expression (e.g., var.x + var.y)
	if operation, ok := attr.Expr.(*hclsyntax.BinaryOpExpr); ok {
		return p.extractBinaryOperation(operation)
	}

	// For other cases where evaluation fails
	// Return a placeholder indicating there was a variable that couldn't be resolved
	return "[VARIABLE_REFERENCE]", nil
}

// extractFunctionCall attempts to extract data from function calls like jsonencode()
func (p *Parser) extractFunctionCall(funcCall *hclsyntax.FunctionCallExpr) (interface{}, error) {
	// Handle jsonencode() function
	if funcCall.Name == "jsonencode" && len(funcCall.Args) > 0 {
		// Try to evaluate the argument to jsonencode
		arg := funcCall.Args[0]
		val, diags := arg.Value(nil)
		if !diags.HasErrors() {
			// Convert to Go value (this should be the object/map before encoding)
			return p.ctyValueToGo(val)
		}
	}
	
	// For other functions or if extraction fails
	return nil, nil
}

// extractResourceFromJSON extracts a resource from a JSON HCL block
func (p *Parser) extractResourceFromJSON(block *hcl.Block, filePath string) (*types.Resource, error) {
	if len(block.Labels) < 2 {
		return nil, fmt.Errorf("resource block missing required labels")
	}

	resourceType := block.Labels[0]
	resourceName := block.Labels[1]
	provider := strings.Split(resourceType, "_")[0]

	// Extract attributes from the block body
	attrs, diags := block.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to extract attributes: %s", diags.Error())
	}

	attributes := make(map[string]interface{})
	for name, attr := range attrs {
		val, err := p.extractAttributeValueFromExpr(attr.Expr)
		if err != nil {
			continue
		}
		attributes[name] = val
	}

	location := types.Location{
		File:   filePath,
		Line:   block.DefRange.Start.Line,
		Column: block.DefRange.Start.Column,
	}

	return &types.Resource{
		ID:         fmt.Sprintf("%s.%s", resourceType, resourceName),
		Type:       resourceType,
		Provider:   provider,
		Name:       resourceName,
		Attributes: attributes,
		Location:   location,
	}, nil
}

// extractDataSourceFromJSON extracts a data source from a JSON HCL block
func (p *Parser) extractDataSourceFromJSON(block *hcl.Block, filePath string) (*types.Resource, error) {
	if len(block.Labels) < 2 {
		return nil, fmt.Errorf("data block missing required labels")
	}

	dataType := block.Labels[0]
	dataName := block.Labels[1]
	provider := strings.Split(dataType, "_")[0]

	// Extract attributes from the block body
	attrs, diags := block.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to extract attributes: %s", diags.Error())
	}

	attributes := make(map[string]interface{})
	for name, attr := range attrs {
		val, err := p.extractAttributeValueFromExpr(attr.Expr)
		if err != nil {
			continue
		}
		attributes[name] = val
	}

	location := types.Location{
		File:   filePath,
		Line:   block.DefRange.Start.Line,
		Column: block.DefRange.Start.Column,
	}

	return &types.Resource{
		ID:         fmt.Sprintf("data.%s.%s", dataType, dataName),
		Type:       fmt.Sprintf("data.%s", dataType),
		Provider:   provider,
		Name:       dataName,
		Attributes: attributes,
		Location:   location,
	}, nil
}

// extractAttributeValueFromExpr extracts value from HCL expression (generic for both HCL and JSON)
func (p *Parser) extractAttributeValueFromExpr(expr hcl.Expression) (interface{}, error) {
	// First try evaluation with the variable context
	val, diags := expr.Value(p.evalContext)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// If evaluation with context fails, try direct evaluation
	val, diags = expr.Value(nil)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// Handle special expression types if possible
	// For JSON files, we don't have access to the specific expression types
	// so we just return a placeholder for unresolved variables
	return "[VARIABLE_REFERENCE]", nil
}

// extractVariableReference extracts a value from a variable reference expression
func (p *Parser) extractVariableReference(expr *hclsyntax.ScopeTraversalExpr) (interface{}, error) {
	// Try to get the variable name from the traversal
	traversal := expr.Traversal
	if len(traversal) < 2 {
		return "[INVALID_VARIABLE_REFERENCE]", nil
	}
	
	// Check if this is a var.xxx reference
	root, ok := traversal[0].(hcl.TraverseRoot)
	if !ok || root.Name != "var" {
		return "[UNSUPPORTED_REFERENCE]", nil
	}
	
	// Get the variable name
	attr, ok := traversal[1].(hcl.TraverseAttr)
	if !ok {
		return "[INVALID_VARIABLE_REFERENCE]", nil
	}
	
	varName := attr.Name
	
	// Look up the variable in our map
	if value, ok := p.variables[varName]; ok {
		// Convert the cty.Value to a Go value
		return p.ctyValueToGo(value)
	}
	
	// Variable not found, return a placeholder
	return fmt.Sprintf("[var.%s]", varName), nil
}

// extractTemplateExpression extracts values from string interpolation expressions like "${var.name}"
func (p *Parser) extractTemplateExpression(expr *hclsyntax.TemplateExpr) (interface{}, error) {
	// If we can evaluate the whole template with variables, do that
	val, diags := expr.Value(p.evalContext)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// Otherwise, try to build a string with placeholders for the parts we can't resolve
	var result strings.Builder
	
	for _, part := range expr.Parts {
		// Try to evaluate this part with variables
		partVal, diags := part.Value(p.evalContext)
		if !diags.HasErrors() {
			// Convert to string and append
			str, err := p.ctyValueToGo(partVal)
			if err == nil {
				result.WriteString(fmt.Sprintf("%v", str))
				continue
			}
		}
		
		// If we can't evaluate with variables, check if it's a variable reference
		if varRef, ok := part.(*hclsyntax.ScopeTraversalExpr); ok {
			val, _ := p.extractVariableReference(varRef)
			result.WriteString(fmt.Sprintf("%v", val))
			continue
		}
		
		// For other expressions, add a placeholder
		result.WriteString("[INTERPOLATED_VALUE]")
	}
	
	return result.String(), nil
}

// extractConditionalExpression handles conditional expressions like: var.enabled ? "yes" : "no"
func (p *Parser) extractConditionalExpression(expr *hclsyntax.ConditionalExpr) (interface{}, error) {
	// Try to evaluate with variables
	val, diags := expr.Value(p.evalContext)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// Create a context-preserving result for security analysis
	conditionalResult := make(map[string]interface{})
	conditionalResult["_type"] = "conditional_expression"
	
	// Try to evaluate the condition
	condVal, condDiags := expr.Condition.Value(p.evalContext)
	if !condDiags.HasErrors() {
		// If condition can be evaluated, store the result
		conditionalResult["_condition_evaluated"] = true
		conditionalResult["_condition_value"] = condVal.True()
		
		// If condition can be evaluated, try to return the appropriate branch
		if condVal.True() {
			// True branch
			trueVal, diags := expr.TrueResult.Value(p.evalContext)
			if !diags.HasErrors() {
				goVal, _ := p.ctyValueToGo(trueVal)
				conditionalResult["_value"] = goVal
				return conditionalResult, nil
			}
		} else {
			// False branch
			falseVal, diags := expr.FalseResult.Value(p.evalContext)
			if !diags.HasErrors() {
				goVal, _ := p.ctyValueToGo(falseVal)
				conditionalResult["_value"] = goVal
				return conditionalResult, nil
			}
		}
	}
	
	// Try to extract condition for analysis
	conditionVal, _ := p.extractGenericExpression(expr.Condition)
	conditionalResult["_condition"] = conditionVal
	
	// Check for environment-based conditions (common security pattern)
	if isEnvCondition := p.isEnvironmentCondition(expr.Condition); isEnvCondition {
		conditionalResult["_environment_condition"] = true
	}
	
	// Check for variable negation (common pattern: !var.secure_mode)
	if isVarNegation, varName := p.isVariableNegation(expr.Condition); isVarNegation {
		conditionalResult["_variable_negation"] = true
		conditionalResult["_negated_variable"] = varName
	}
	
	// Extract both branches
	var trueValue, falseValue interface{}
	
	// Extract the true value
	trueValue, _ = p.extractGenericExpression(expr.TrueResult)
	conditionalResult["_true_value"] = trueValue
	
	// Extract the false value
	falseValue, _ = p.extractGenericExpression(expr.FalseResult)
	conditionalResult["_false_value"] = falseValue
	
	// For security analysis, use the least secure option by default
	conditionalResult["_security_analysis"] = "worst_case"
	conditionalResult["_security_value"] = p.leastSecureOption(trueValue, falseValue)
	
	// For backward compatibility, also return a string representation
	conditionalResult["_string_value"] = fmt.Sprintf("[CONDITIONAL: %v OR %v]", trueValue, falseValue)
	
	return conditionalResult, nil
}

// Helper to check if a condition is likely comparing an environment variable
func (p *Parser) isEnvironmentCondition(condition hclsyntax.Expression) bool {
	// Check if it's a binary operation
	if binaryOp, ok := condition.(*hclsyntax.BinaryOpExpr); ok {
		// Check if either side is a variable reference
		if leftVar, isLeft := binaryOp.LHS.(*hclsyntax.ScopeTraversalExpr); isLeft {
			return p.isEnvironmentVar(leftVar)
		}
		if rightVar, isRight := binaryOp.RHS.(*hclsyntax.ScopeTraversalExpr); isRight {
			return p.isEnvironmentVar(rightVar)
		}
	}
	return false
}

// Helper to check if a variable reference likely refers to environment
func (p *Parser) isEnvironmentVar(expr *hclsyntax.ScopeTraversalExpr) bool {
	// Traverse the variable path
	if len(expr.Traversal) < 2 {
		return false
	}
	
	// Check if it's a var reference
	root, ok := expr.Traversal[0].(hcl.TraverseRoot)
	if !ok || root.Name != "var" {
		return false
	}
	
	// Check the variable name
	attr, ok := expr.Traversal[1].(hcl.TraverseAttr)
	if !ok {
		return false
	}
	
	// Common environment variable names
	envVarNames := []string{"environment", "env", "stage", "production", "prod_mode", "production_mode"}
	for _, name := range envVarNames {
		if attr.Name == name || strings.Contains(attr.Name, "environment") || strings.Contains(attr.Name, "env") {
			return true
		}
	}
	
	return false
}

// Helper to determine which option is least secure for security analysis
func (p *Parser) leastSecureOption(val1, val2 interface{}) interface{} {
	// For string values, check known insecure values
	str1, isStr1 := val1.(string)
	str2, isStr2 := val2.(string)
	
	if isStr1 && isStr2 {
		// Known less secure values (precedence order)
		lessSecureValues := []string{
			"public-read-write",
			"public-read", 
			"authenticated-read", 
			"private",
			"false",
			"0",
		}
		
		// Check which value is less secure
		for _, insecure := range lessSecureValues {
			if str1 == insecure {
				return val1
			}
			if str2 == insecure {
				return val2
			}
		}
	}
	
	// For boolean values, false is typically less secure
	bool1, isBool1 := val1.(bool)
	bool2, isBool2 := val2.(bool)
	
	if isBool1 && isBool2 {
		if !bool1 && bool2 {
			return val1
		}
		if bool1 && !bool2 {
			return val2
		}
	}
	
	// For numbers, lower is typically less secure (retention periods, etc)
	num1, isNum1 := val1.(float64)
	num2, isNum2 := val2.(float64)
	
	if isNum1 && isNum2 {
		if num1 < num2 {
			return val1
		}
		if num2 < num1 {
			return val2
		}
	}
	
	// Check for conditional values embedded in maps
	condMap1, isCond1 := val1.(map[string]interface{})
	condMap2, isCond2 := val2.(map[string]interface{})
	
	if isCond1 {
		if typeVal, ok := condMap1["_type"].(string); ok && typeVal == "conditional_expression" {
			if secVal, ok := condMap1["_security_value"]; ok {
				val1 = secVal // Use the security value for comparison
			}
		}
	}
	
	if isCond2 {
		if typeVal, ok := condMap2["_type"].(string); ok && typeVal == "conditional_expression" {
			if secVal, ok := condMap2["_security_value"]; ok {
				val2 = secVal // Use the security value for comparison
			}
		}
	}
	
	// If we can't determine, return both for analysis
	return []interface{}{val1, val2}
}

// extractBinaryOperation handles binary operations like: var.count + 1
func (p *Parser) extractBinaryOperation(expr *hclsyntax.BinaryOpExpr) (interface{}, error) {
	// Try to evaluate with variables
	val, diags := expr.Value(p.evalContext)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// Extract left and right operands
	leftVal, leftErr := p.extractGenericExpression(expr.LHS)
	if leftErr != nil {
		leftVal = "[LEFT_OPERAND]"
	}
	
	rightVal, rightErr := p.extractGenericExpression(expr.RHS)
	if rightErr != nil {
		rightVal = "[RIGHT_OPERAND]"
	}
	
	// Get the operation symbol
	var opStr string
	switch expr.Op {
	case hclsyntax.OpAdd:
		opStr = "+"
	case hclsyntax.OpSubtract:
		opStr = "-"
	case hclsyntax.OpMultiply:
		opStr = "*"
	case hclsyntax.OpDivide:
		opStr = "/"
	case hclsyntax.OpEqual:
		opStr = "=="
	case hclsyntax.OpNotEqual:
		opStr = "!="
	case hclsyntax.OpGreaterThan:
		opStr = ">"
	case hclsyntax.OpGreaterThanOrEqual:
		opStr = ">="
	case hclsyntax.OpLessThan:
		opStr = "<"
	case hclsyntax.OpLessThanOrEqual:
		opStr = "<="
	case hclsyntax.OpLogicalAnd:
		opStr = "&&"
	case hclsyntax.OpLogicalOr:
		opStr = "||"
	default:
		opStr = "??"
	}
	
	// Return a placeholder with the operation
	return fmt.Sprintf("[OPERATION: %v %s %v]", leftVal, opStr, rightVal), nil
}

// extractGenericExpression handles any type of expression by dispatching to specific handlers
func (p *Parser) extractGenericExpression(expr hclsyntax.Expression) (interface{}, error) {
	// Try evaluation with the variable context
	val, diags := expr.Value(p.evalContext)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	
	// If that fails, check the expression type
	switch e := expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		return p.extractVariableReference(e)
	case *hclsyntax.TemplateExpr:
		return p.extractTemplateExpression(e)
	case *hclsyntax.ConditionalExpr:
		return p.extractConditionalExpression(e)
	case *hclsyntax.BinaryOpExpr:
		return p.extractBinaryOperation(e)
	case *hclsyntax.FunctionCallExpr:
		return p.extractFunctionCall(e)
	case *hclsyntax.LiteralValueExpr:
		val, _ := e.Value(nil)
		return p.ctyValueToGo(val)
	default:
		return "[EXPRESSION]", fmt.Errorf("unsupported expression type: %T", expr)
	}
}

// extractModuleInfo extracts information from a module block in HCL syntax
func (p *Parser) extractModuleInfo(block *hclsyntax.Block, filePath string) (*types.Resource, error) {
	if len(block.Labels) < 1 {
		return nil, fmt.Errorf("module block missing required name label")
	}

	moduleName := block.Labels[0]
	attributes := make(map[string]interface{})
	
	// Extract all attributes, especially 'source' which is required
	for name, attr := range block.Body.Attributes {
		val, err := p.extractAttributeValue(attr)
		if err != nil {
			continue
		}
		attributes[name] = val
	}

	// Extract any nested blocks (module configurations can have them)
	blocksByType := make(map[string][]map[string]interface{})
	for _, nestedBlock := range block.Body.Blocks {
		nestedAttrs, err := p.extractNestedBlock(nestedBlock)
		if err != nil {
			continue
		}
		blocksByType[nestedBlock.Type] = append(blocksByType[nestedBlock.Type], nestedAttrs)
	}
	
	// Add blocks to attributes
	for blockType, blocks := range blocksByType {
		if len(blocks) == 1 {
			attributes[blockType] = blocks[0]
		} else {
			attributes[blockType] = blocks
		}
	}

	// Create a special type of resource for modules
	location := types.Location{
		File:   filePath,
		Line:   block.TypeRange.Start.Line,
		Column: block.TypeRange.Start.Column,
	}

	return &types.Resource{
		ID:         fmt.Sprintf("module.%s", moduleName),
		Type:       "module",
		Provider:   "terraform",
		Name:       moduleName,
		Attributes: attributes,
		Location:   location,
	}, nil
}

// extractModuleInfoFromJSON extracts information from a module block in JSON syntax
func (p *Parser) extractModuleInfoFromJSON(block *hcl.Block, filePath string) (*types.Resource, error) {
	if len(block.Labels) < 1 {
		return nil, fmt.Errorf("module block missing required name label")
	}

	moduleName := block.Labels[0]
	
	// Extract attributes from the block body
	attrs, diags := block.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to extract module attributes: %s", diags.Error())
	}

	attributes := make(map[string]interface{})
	for name, attr := range attrs {
		val, err := p.extractAttributeValueFromExpr(attr.Expr)
		if err != nil {
			continue
		}
		attributes[name] = val
	}

	location := types.Location{
		File:   filePath,
		Line:   block.DefRange.Start.Line,
		Column: block.DefRange.Start.Column,
	}

	return &types.Resource{
		ID:         fmt.Sprintf("module.%s", moduleName),
		Type:       "module",
		Provider:   "terraform",
		Name:       moduleName,
		Attributes: attributes,
		Location:   location,
	}, nil
}

// ctyValueToGo converts a cty.Value to a Go value
func (p *Parser) ctyValueToGo(val cty.Value) (interface{}, error) {
	if val.IsNull() {
		return nil, nil
	}

	if !val.IsKnown() {
		return nil, fmt.Errorf("unknown value")
	}

	switch {
	case val.Type() == cty.String:
		return val.AsString(), nil
	case val.Type() == cty.Number:
		bf := val.AsBigFloat()
		f, _ := bf.Float64()
		return f, nil
	case val.Type() == cty.Bool:
		return val.True(), nil
	case val.Type().IsListType() || val.Type().IsTupleType():
		var result []interface{}
		for it := val.ElementIterator(); it.Next(); {
			_, elem := it.Element()
			converted, err := p.ctyValueToGo(elem)
			if err != nil {
				continue
			}
			result = append(result, converted)
		}
		return result, nil
	case val.Type().IsMapType() || val.Type().IsObjectType():
		result := make(map[string]interface{})
		for it := val.ElementIterator(); it.Next(); {
			key, elem := it.Element()
			keyStr := key.AsString()
			converted, err := p.ctyValueToGo(elem)
			if err != nil {
				continue
			}
			result[keyStr] = converted
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported type: %s", val.Type().FriendlyName())
	}
}

// isSecurityCriticalVariable determines if a variable is security-relevant
func (p *Parser) isSecurityCriticalVariable(name string, value interface{}) bool {
	// Common security-critical variable names
	securityVarNames := []string{
		"publicly_accessible", "public", "public_access",
		"storage_encrypted", "encrypted", "encryption", "encrypt",
		"backup", "backup_retention", "retention",
		"multi_az", "deletion_protection", "delete_protection",
		"iam_database_authentication", "iam_auth",
		"log", "logs", "cloudwatch", "audit",
		"parameter_group", "parameter",
		"security", "secure", "insecure",
		"production", "prod", "environment", "env",
	}

	// High-priority security boolean variables that must be specially tracked
	securityBooleanVars := map[string]bool{
		"publicly_accessible": true, 
		"storage_encrypted": true,
		"multi_az": true,
		"deletion_protection": true,
		"iam_database_authentication_enabled": true,
		"performance_insights_enabled": true,
	}

	// Direct match for critical security boolean variables
	if _, ok := securityBooleanVars[name]; ok {
		return true
	}

	// Check variable name against known security-critical names
	for _, secVarName := range securityVarNames {
		if strings.Contains(strings.ToLower(name), secVarName) {
			return true
		}
	}

	// Check if it's a boolean or conditional, which might be security-relevant
	switch v := value.(type) {
	case bool:
		return true // All booleans could be security switches
	case map[string]interface{}:
		// Check if it's a conditional expression
		if typeVal, ok := v["_type"]; ok && typeVal == "conditional_expression" {
			return true
		}
	}

	return false
}

// isSecurityAttributeName checks if an attribute name is security-critical
func (p *Parser) isSecurityAttributeName(name string) bool {
	// Known security-critical attribute names
	securityAttrs := []string{
		"publicly_accessible", "public_access",
		"storage_encrypted", "encrypted",
		"backup_retention_period",
		"multi_az", "deletion_protection",
		"iam_database_authentication_enabled",
		"enabled_cloudwatch_logs_exports",
		"parameter_group_name",
		"tags.Environment", "environment",
	}

	for _, attr := range securityAttrs {
		if name == attr {
			return true
		}
	}

	return false
}

// getCurrentAttributeName tries to determine the parent attribute name for contextual analysis
func (p *Parser) getCurrentAttributeName(expr hclsyntax.Expression) string {
	// This is a simplification - in a real implementation, you would need to track
	// the parent attribute during recursive descent parsing
	return "" // Default to empty, to be enhanced in future versions
}

// isVariableNegation checks if the condition is negating a variable (like !var.secure_mode)
func (p *Parser) isVariableNegation(condition hclsyntax.Expression) (bool, string) {
	// Check if it's a unary operation with NOT
	if unaryOp, ok := condition.(*hclsyntax.UnaryOpExpr); ok && unaryOp.Op == hclsyntax.OpLogicalNot {
		// Check if the operand is a variable reference
		if varRef, ok := unaryOp.Val.(*hclsyntax.ScopeTraversalExpr); ok {
			// Extract variable name if possible
			if len(varRef.Traversal) >= 2 {
				if rootName, ok := varRef.Traversal[0].(hcl.TraverseRoot); ok && rootName.Name == "var" {
					if attrName, ok := varRef.Traversal[1].(hcl.TraverseAttr); ok {
						return true, attrName.Name
					}
				}
			}
		}
	}

	return false, ""
}

// enhanceCriticalRdsSecurityAttributes adds special security indicators for critical RDS settings
func (p *Parser) enhanceCriticalRdsSecurityAttributes(attrs map[string]interface{}) {
	// Check for direct insecure boolean values
	type criticalAttrInfo struct {
		attrName    string
		insecureVal bool
		securityKey string
	}
	
	criticalBooleanAttrs := []criticalAttrInfo{
		{"publicly_accessible", true, "_security_publicly_accessible"},
		{"storage_encrypted", false, "_security_unencrypted"},
		{"iam_database_authentication_enabled", false, "_security_no_iam_auth"},
		{"deletion_protection", false, "_security_no_deletion_protection"},
	}
	
	// Check each critical boolean attribute
	for _, critAttr := range criticalBooleanAttrs {
		if attrVal, exists := attrs[critAttr.attrName]; exists {
			// Direct boolean value
			if boolVal, isBool := attrVal.(bool); isBool && boolVal == critAttr.insecureVal {
				// This is a potential security issue
				attrs[critAttr.securityKey] = true
			}
			
			// Enhanced attribute with security context
			if enhAttr, isEnh := attrVal.(map[string]interface{}); isEnh {
				if typeVal, hasType := enhAttr["_type"]; hasType && 
				   (typeVal == "security_enhanced_attribute" || typeVal == "conditional_expression") {
					// Check security value
					if secVal, hasSec := enhAttr["_security_value"]; hasSec {
						if boolVal, isBool := secVal.(bool); isBool && boolVal == critAttr.insecureVal {
							// This is a potential security issue
							attrs[critAttr.securityKey] = true
						}
					}
				}
			}
		}
	}
	
	// Special handling for backup_retention_period
	if retPeriod, exists := attrs["backup_retention_period"]; exists {
		// Check direct value
		if numVal, isNum := retPeriod.(float64); isNum && numVal == 0 {
			// Backups disabled - security issue
			attrs["_security_no_backup"] = true
		}
		
		// Check enhanced value
		if enhAttr, isEnh := retPeriod.(map[string]interface{}); isEnh {
			if typeVal, hasType := enhAttr["_type"]; hasType && 
			   (typeVal == "security_enhanced_attribute" || typeVal == "conditional_expression") {
				// Check security value
				if secVal, hasSec := enhAttr["_security_value"]; hasSec {
					if numVal, isNum := secVal.(float64); isNum && numVal == 0 {
						// This is a potential security issue
						attrs["_security_no_backup"] = true
					}
				}
			}
		}
	}
	
	// Special handling for enabled_cloudwatch_logs_exports
	if logExports, exists := attrs["enabled_cloudwatch_logs_exports"]; exists {
		// Check if it's empty
		if arr, isArr := logExports.([]interface{}); isArr && len(arr) == 0 {
			attrs["_security_no_log_exports"] = true
		}
		
		// Check enhanced value
		if enhAttr, isEnh := logExports.(map[string]interface{}); isEnh {
			if typeVal, hasType := enhAttr["_type"]; hasType && 
			   (typeVal == "security_enhanced_attribute" || typeVal == "conditional_expression") {
				// Check security value
				if secVal, hasSec := enhAttr["_security_value"]; hasSec {
					if arr, isArr := secVal.([]interface{}); isArr && len(arr) == 0 {
						// This is a potential security issue
						attrs["_security_no_log_exports"] = true
					}
				}
			}
		}
	}
	
	// Special handling for parameter_group_name
	if pgName, exists := attrs["parameter_group_name"]; exists {
		// Check if it contains "default"
		if strVal, isStr := pgName.(string); isStr && strings.Contains(strVal, "default") {
			attrs["_security_default_parameter_group"] = true
		}
		
		// Check enhanced value
		if enhAttr, isEnh := pgName.(map[string]interface{}); isEnh {
			if typeVal, hasType := enhAttr["_type"]; hasType && 
			   (typeVal == "security_enhanced_attribute" || typeVal == "conditional_expression") {
				// Check security value
				if secVal, hasSec := enhAttr["_security_value"]; hasSec {
					if strVal, isStr := secVal.(string); isStr && strings.Contains(strVal, "default") {
						// This is a potential security issue
						attrs["_security_default_parameter_group"] = true
					}
				}
			}
		}
	}
}

// enhanceSecurityAttributesFromModuleVars enhances resource attributes with module variables
func (p *Parser) enhanceSecurityAttributesFromModuleVars(resource types.Resource, moduleVars map[string]interface{}) {
	// Skip non-RDS resources
	if !strings.HasPrefix(resource.Type, "aws_db_instance") && 
	   !strings.HasPrefix(resource.Type, "aws_rds_cluster") {
		return
	}
	
	// Get the attributes map
	attrs := resource.Attributes
	if attrs == nil {
		return
	}
	
	// Add module-specific security metadata
	attrs["_resource_in_module"] = true
	
	// Special handling for critical RDS security attributes
	p.enhanceCriticalRdsSecurityAttributes(attrs)
	
	// RDS security-critical attributes to enhance with module variable context
	securityAttrs := []string{
		"publicly_accessible", 
		"storage_encrypted", 
		"backup_retention_period",
		"multi_az", 
		"deletion_protection",
		"iam_database_authentication_enabled",
		"enabled_cloudwatch_logs_exports",
		"parameter_group_name",
	}
	
	// Add security context to these attributes
	for _, attrName := range securityAttrs {
		if attrVal, exists := attrs[attrName]; exists {
			// If the attribute is directly from a module variable, add context
			if varRef, isRef := attrVal.(string); isRef && strings.HasPrefix(varRef, "[var.") {
				// Extract variable name
				varName := strings.TrimPrefix(strings.TrimSuffix(varRef, "]"), "[var.")
				
				// Look for the variable in module variables
				if moduleVal, ok := moduleVars[varName]; ok {
					// Create an enhanced attribute with security context
					enhancedAttr := make(map[string]interface{})
					enhancedAttr["_type"] = "security_enhanced_attribute"
					enhancedAttr["_original_value"] = attrVal
					enhancedAttr["_variable_name"] = varName
					enhancedAttr["_module_value"] = moduleVal
					
					// For security analysis, determine the worst-case value
					if condMap, isCond := moduleVal.(map[string]interface{}); isCond && 
					   condMap["_type"] == "conditional_expression" {
						if secVal, hasSec := condMap["_security_value"]; hasSec {
							enhancedAttr["_security_value"] = secVal
						}
					} else {
						enhancedAttr["_security_value"] = moduleVal
					}
					
					// Replace the attribute with the enhanced version
					attrs[attrName] = enhancedAttr
					
					// Special handling for specific RDS security attributes
					switch attrName {
					case "publicly_accessible":
						// For publicly_accessible, also add a direct attribute for policy evaluation
						if boolVal, isBool := enhancedAttr["_security_value"].(bool); isBool && boolVal {
							// This is a potential security issue - make it visible to policies
							attrs["_security_publicly_accessible"] = true
							p.log.Debug("Enhanced attribute security marker: _security_publicly_accessible = true for %s", resource.ID)
						}
					case "storage_encrypted":
						// For storage_encrypted, also add a direct attribute for policy evaluation
						if boolVal, isBool := enhancedAttr["_security_value"].(bool); isBool && !boolVal {
							// This is a potential security issue - make it visible to policies
							attrs["_security_unencrypted"] = true
							p.log.Debug("Enhanced attribute security marker: _security_unencrypted = true for %s", resource.ID)
						}
					case "backup_retention_period":
						// For backup_retention_period, add context for policies
						if numVal, isNum := enhancedAttr["_security_value"].(float64); isNum && numVal == 0 {
							// This is a potential security issue - make it visible to policies
							attrs["_security_no_backup"] = true
							p.log.Debug("Enhanced attribute security marker: _security_no_backup = true for %s", resource.ID)
						}
					}
				}
			}
			
			// If the attribute is a conditional expression itself, ensure it has security context
			if condMap, isCond := attrVal.(map[string]interface{}); isCond && 
			   condMap["_type"] == "conditional_expression" {
				// Make sure it's marked as a security attribute
				condMap["_security_critical"] = true
				condMap["_attribute_name"] = attrName
				
				// Add specialized handling based on attribute name
				switch attrName {
				case "publicly_accessible":
					// For publicly_accessible, check if the security value is true
					if secVal, ok := condMap["_security_value"]; ok {
						if boolVal, isBool := secVal.(bool); isBool && boolVal {
							attrs["_security_publicly_accessible"] = true
							p.log.Debug("Conditional security marker: _security_publicly_accessible = true for %s", resource.ID)
						}
					}
				case "storage_encrypted":
					// For storage_encrypted, check if the security value is false
					if secVal, ok := condMap["_security_value"]; ok {
						if boolVal, isBool := secVal.(bool); isBool && !boolVal {
							attrs["_security_unencrypted"] = true
							p.log.Debug("Conditional security marker: _security_unencrypted = true for %s", resource.ID)
						}
					}
				case "backup_retention_period":
					// For backup_retention_period, check if the security value is 0
					if secVal, ok := condMap["_security_value"]; ok {
						if numVal, isNum := secVal.(float64); isNum && numVal == 0 {
							attrs["_security_no_backup"] = true
							p.log.Debug("Conditional security marker: _security_no_backup = true for %s", resource.ID)
						}
					}
				case "iam_database_authentication_enabled":
					// For iam_database_authentication_enabled, check if the security value is false
					if secVal, ok := condMap["_security_value"]; ok {
						if boolVal, isBool := secVal.(bool); isBool && !boolVal {
							attrs["_security_no_iam_auth"] = true
							p.log.Debug("Conditional security marker: _security_no_iam_auth = true for %s", resource.ID)
						}
					}
				}
			}
		}
	}
	
	// Handle boolean values directly - especially for module variables like in variable_db
	for varName, varValue := range moduleVars {
		// Handle direct boolean values that might be security critical
		if boolVal, isBool := varValue.(bool); isBool {
			switch varName {
			case "publicly_accessible":
				if boolVal { // true is insecure
					attrs["_security_publicly_accessible"] = true
					p.log.Debug("Direct module var security marker: _security_publicly_accessible = true for %s", resource.ID)
				}
			case "storage_encrypted":
				if !boolVal { // false is insecure
					attrs["_security_unencrypted"] = true
					p.log.Debug("Direct module var security marker: _security_unencrypted = true for %s", resource.ID)
				}
			case "iam_database_authentication_enabled":
				if !boolVal { // false is insecure
					attrs["_security_no_iam_auth"] = true
					p.log.Debug("Direct module var security marker: _security_no_iam_auth = true for %s", resource.ID)
				}
			case "deletion_protection":
				if !boolVal { // false is insecure
					attrs["_security_no_deletion_protection"] = true
					p.log.Debug("Direct module var security marker: _security_no_deletion_protection = true for %s", resource.ID)
				}
			}
		}
		
		// Handle numeric values like backup_retention_period
		if numVal, isNum := varValue.(float64); isNum && varName == "backup_retention_period" && numVal == 0 {
			attrs["_security_no_backup"] = true
			p.log.Debug("Direct module var security marker: _security_no_backup = true for %s", resource.ID)
		}
		
		// Handle conditional expressions in module variables
		if condMap, isCond := varValue.(map[string]interface{}); isCond && condMap["_type"] == "conditional_expression" {
			if secVal, hasSec := condMap["_security_value"]; hasSec {
				switch varName {
				case "publicly_accessible":
					if bVal, isBool := secVal.(bool); isBool && bVal {
						attrs["_security_publicly_accessible"] = true
						p.log.Debug("Module conditional security marker: _security_publicly_accessible = true for %s", resource.ID)
					}
				case "storage_encrypted":
					if bVal, isBool := secVal.(bool); isBool && !bVal {
						attrs["_security_unencrypted"] = true
						p.log.Debug("Module conditional security marker: _security_unencrypted = true for %s", resource.ID)
					}
				case "backup_retention_period":
					if numVal, isNum := secVal.(float64); isNum && numVal == 0 {
						attrs["_security_no_backup"] = true
						p.log.Debug("Module conditional security marker: _security_no_backup = true for %s", resource.ID)
					}
				}
			}
		}
	}
	
	// Handle special case for tags
	if tags, hasTags := attrs["tags"].(map[string]interface{}); hasTags {
		// Check for environment tag
		if envTag, hasEnv := tags["Environment"]; hasEnv {
			// If it's a production environment, add metadata for policy checks
			if envStr, isStr := envTag.(string); isStr && 
			   (envStr == "production" || envStr == "prod") {
				attrs["_is_production"] = true
				
				// For production environments, multi-AZ and deletion protection should be enabled
				if multiAz, hasMultiAz := attrs["multi_az"]; hasMultiAz {
					if boolVal, isBool := multiAz.(bool); isBool && !boolVal {
						// This is a potential security issue for production environments
						attrs["_security_no_multi_az_prod"] = true
					}
				}
				
				if delProtection, hasDelProtection := attrs["deletion_protection"]; hasDelProtection {
					if boolVal, isBool := delProtection.(bool); isBool && !boolVal {
						// This is a potential security issue for production environments
						attrs["_security_no_deletion_protection_prod"] = true
					}
				}
			}
		}
	}
	
	// No need to update resource.Attributes since we're modifying the map directly
	// The map is passed by reference, so changes are reflected in the original
}