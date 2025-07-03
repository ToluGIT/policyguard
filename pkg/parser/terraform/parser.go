package terraform

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/ToluGIT/policyguard/pkg/types"
	"github.com/zclconf/go-cty/cty"
)

// Parser implements the parser.Parser interface for Terraform files
type Parser struct {
	parser *hclparse.Parser
}

// New creates a new Terraform parser
func New() *Parser {
	return &Parser{
		parser: hclparse.NewParser(),
	}
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

	return p.extractResources(file, filePath)
}

// ParseDirectory parses all Terraform and OpenTofu files in a directory
func (p *Parser) ParseDirectory(ctx context.Context, dirPath string) ([]types.Resource, error) {
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

	var allResources []types.Resource
	for _, file := range allFiles {
		resources, err := p.Parse(ctx, file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}
		allResources = append(allResources, resources...)
	}

	return allResources, nil
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
			}
		}
		return resources, nil
	}

	// Handle JSON files (.tf.json, .tofu.json) - they use the generic HCL body interface
	content, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "resource", LabelNames: []string{"type", "name"}},
			{Type: "data", LabelNames: []string{"type", "name"}},
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
	// First try direct evaluation
	val, diags := attr.Expr.Value(nil)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}

	// If direct evaluation fails, check if it's a function call
	if funcCall, ok := attr.Expr.(*hclsyntax.FunctionCallExpr); ok {
		return p.extractFunctionCall(funcCall)
	}

	// For other cases where evaluation fails (like variable references)
	return nil, nil
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
	val, diags := expr.Value(nil)
	if !diags.HasErrors() {
		return p.ctyValueToGo(val)
	}
	return nil, nil
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