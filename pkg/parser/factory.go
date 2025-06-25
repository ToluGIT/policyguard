package parser

import (
	"fmt"
	"strings"
	"sync"
)

// DefaultFactory is the default parser factory implementation
type DefaultFactory struct {
	parsers map[string]Parser
	mu      sync.RWMutex
}

// NewFactory creates a new parser factory
func NewFactory() *DefaultFactory {
	return &DefaultFactory{
		parsers: make(map[string]Parser),
	}
}

// GetParser returns a parser for the given file type
func (f *DefaultFactory) GetParser(fileType string) (Parser, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	fileType = strings.ToLower(fileType)
	parser, ok := f.parsers[fileType]
	if !ok {
		return nil, fmt.Errorf("no parser registered for file type: %s", fileType)
	}

	return parser, nil
}

// RegisterParser registers a new parser for a file type
func (f *DefaultFactory) RegisterParser(fileType string, parser Parser) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	fileType = strings.ToLower(fileType)
	if _, exists := f.parsers[fileType]; exists {
		return fmt.Errorf("parser already registered for file type: %s", fileType)
	}

	f.parsers[fileType] = parser
	return nil
}

// GetParserByExtension returns a parser based on file extension
func (f *DefaultFactory) GetParserByExtension(extension string) (Parser, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	extension = strings.ToLower(extension)
	
	// Check each registered parser's supported extensions
	for _, parser := range f.parsers {
		for _, ext := range parser.SupportedExtensions() {
			if strings.ToLower(ext) == extension {
				return parser, nil
			}
		}
	}

	return nil, fmt.Errorf("no parser found for extension: %s", extension)
}