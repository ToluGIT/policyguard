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
	}
	
	// Initialize the evaluation context
	p.initEvalContext()
	
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
			fmt.Printf("Warning: Error extracting variables from %s: %v\n", filePath, err)
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
		fmt.Printf("Warning: Error extracting variables: %v\n", err)
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
		fmt.Printf("Warning: Error resolving modules: %v\n", err)
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
					fmt.Printf("Warning: Failed to extract variable %s: %v\n", varName, err)
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
				fmt.Printf("Warning: Failed to extract variable %s from JSON: %v\n", varName, err)
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
		
		// Debug: Print extracted variables
		val, err := p.ctyValueToGo(v)
		if err == nil {
			fmt.Printf("DEBUG: Extracted variable %s = %v\n", k, val)
		} else {
			fmt.Printf("DEBUG: Extracted variable %s (error converting: %v)\n", k, err)
		}
	}
	
	// Only create the object if we have variables
	if len(varMap) > 0 {
		// Try to create the object value
		objectVal, err := cty.ObjectVal(varMap), error(nil)
		if err != nil {
			fmt.Printf("Warning: Error creating variable object: %v\n", err)
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
			continue
		}
		
		// Handle local modules (starting with ./ or ../)
		if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			// Resolve relative path
			modulePath := filepath.Join(basePath, source)
			
			// Check if the path exists
			if _, err := os.Stat(modulePath); os.IsNotExist(err) {
				// Module path doesn't exist, skip
				continue
			}
			
			// Parse module directory
			resources, err := p.ParseModuleDirectory(ctx, modulePath, module.Name)
			if err != nil {
				// Log the error but continue with other modules
				fmt.Printf("Warning: Failed to parse module %s: %v\n", module.Name, err)
				continue
			}
			
			moduleResources = append(moduleResources, resources...)
		} else {
			// For non-local modules (remote registry, git, etc.), we'd need to download them first
			// For now, we'll just log that we can't handle them yet
			fmt.Printf("Note: Skipping remote module %s with source %s\n", module.Name, source)
		}
	}
	
	return moduleResources, nil
}

// ParseModuleDirectory parses a module directory and adds module context to resources
func (p *Parser) ParseModuleDirectory(ctx context.Context, modulePath string, moduleName string) ([]types.Resource, error) {
	// Parse the module directory normally
	resources, err := p.ParseDirectory(ctx, modulePath)
	if err != nil {
		return nil, err
	}
	
	// Add module context to all resources
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
	}
	
	return resources, nil
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
					fmt.Printf("Warning: Failed to extract module info: %v\n", err)
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
				fmt.Printf("Warning: Failed to extract module info from JSON: %v\n", err)
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
	
	// Extract attributes
	for name, attr := range block.Body.Attributes {
		val, err := p.extractAttributeValue(attr)
		if err != nil {
			continue
		}
		result[name] = val
		
		// Special debug for encryption settings
		if name == "sse_algorithm" || name == "kms_master_key_id" {
			fmt.Printf("DEBUG: Nested attribute %s.%s = %v\n", block.Type, name, val)
		}
	}

	// Handle nested blocks recursively
	for _, nestedBlock := range block.Body.Blocks {
		nestedAttrs, err := p.extractNestedBlock(nestedBlock)
		if err != nil {
			continue
		}
		result[nestedBlock.Type] = nestedAttrs
		
		// Special debug for server_side_encryption blocks
		if block.Type == "server_side_encryption_configuration" || 
		   block.Type == "rule" || 
		   block.Type == "apply_server_side_encryption_by_default" {
			fmt.Printf("DEBUG: Found nested block %s > %s\n", block.Type, nestedBlock.Type)
		}
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
	
	// Try to evaluate the condition
	condVal, diags := expr.Condition.Value(p.evalContext)
	if !diags.HasErrors() {
		// If condition can be evaluated, try to return the appropriate branch
		if condVal.True() {
			// True branch
			trueVal, diags := expr.TrueResult.Value(p.evalContext)
			if !diags.HasErrors() {
				return p.ctyValueToGo(trueVal)
			}
			
			// Try to extract the true value even if it can't be fully evaluated
			if trueRef, ok := expr.TrueResult.(*hclsyntax.ScopeTraversalExpr); ok {
				return p.extractVariableReference(trueRef)
			}
		} else {
			// False branch
			falseVal, diags := expr.FalseResult.Value(p.evalContext)
			if !diags.HasErrors() {
				return p.ctyValueToGo(falseVal)
			}
			
			// Try to extract the false value even if it can't be fully evaluated
			if falseRef, ok := expr.FalseResult.(*hclsyntax.ScopeTraversalExpr); ok {
				return p.extractVariableReference(falseRef)
			}
		}
	}
	
	// If we can't evaluate, try to extract both values
	var trueValue, falseValue interface{}
	var err error
	
	// Extract the true value
	if trueRef, ok := expr.TrueResult.(*hclsyntax.ScopeTraversalExpr); ok {
		trueValue, _ = p.extractVariableReference(trueRef)
	} else {
		trueValue, err = p.extractGenericExpression(expr.TrueResult)
		if err != nil {
			trueValue = "[TRUE_VALUE]"
		}
	}
	
	// Extract the false value
	if falseRef, ok := expr.FalseResult.(*hclsyntax.ScopeTraversalExpr); ok {
		falseValue, _ = p.extractVariableReference(falseRef)
	} else {
		falseValue, err = p.extractGenericExpression(expr.FalseResult)
		if err != nil {
			falseValue = "[FALSE_VALUE]"
		}
	}
	
	// Return a placeholder with the possible values
	return fmt.Sprintf("[CONDITIONAL: %v OR %v]", trueValue, falseValue), nil
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