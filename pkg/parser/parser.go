package parser

import (
	"context"
	"github.com/policyguard/policyguard/pkg/types"
)

// Parser defines the interface for parsing IaC files
type Parser interface {
	// Parse parses the given file and returns extracted resources
	Parse(ctx context.Context, filePath string) ([]types.Resource, error)
	
	// ParseDirectory parses all compatible files in a directory
	ParseDirectory(ctx context.Context, dirPath string) ([]types.Resource, error)
	
	// SupportedExtensions returns the file extensions this parser supports
	SupportedExtensions() []string
}

// ParserFactory creates parser instances based on file type
type ParserFactory interface {
	// GetParser returns a parser for the given file type
	GetParser(fileType string) (Parser, error)
	
	// RegisterParser registers a new parser for a file type
	RegisterParser(fileType string, parser Parser) error
}