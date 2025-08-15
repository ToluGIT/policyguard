package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	
	"github.com/ToluGIT/policyguard/pkg/types"
)

// SeverityConfig represents the policy severity configuration
type SeverityConfig struct {
	Description     string            `json:"description"`
	DefaultSeverity string            `json:"default_severity"`
	Severities      map[string]string `json:"severities"`
}

// NewDefaultSeverityConfig creates a default severity configuration
func NewDefaultSeverityConfig() *SeverityConfig {
	return &SeverityConfig{
		Description:     "Default policy severity configuration",
		DefaultSeverity: types.SeverityMedium,
		Severities:      make(map[string]string),
	}
}

// LoadSeverityConfig loads a severity configuration from a file
func LoadSeverityConfig(configPath string) (*SeverityConfig, error) {
	// If no config path provided, return the default configuration
	if configPath == "" {
		return NewDefaultSeverityConfig(), nil
	}

	// Read the configuration file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read severity configuration: %w", err)
	}

	// Parse JSON
	config := &SeverityConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse severity configuration: %w", err)
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid severity configuration: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *SeverityConfig) Validate() error {
	// Check if default severity is valid
	if !isValidSeverity(c.DefaultSeverity) {
		return fmt.Errorf("invalid default severity: %s", c.DefaultSeverity)
	}

	// Validate severities
	for policyID, severity := range c.Severities {
		if !isValidSeverity(severity) {
			return fmt.Errorf("invalid severity '%s' for policy '%s'", severity, policyID)
		}
	}

	return nil
}

// isValidSeverity checks if a severity string is valid
func isValidSeverity(severity string) bool {
	severity = strings.ToLower(severity)
	return severity == types.SeverityCritical ||
		severity == types.SeverityHigh ||
		severity == types.SeverityMedium ||
		severity == types.SeverityLow ||
		severity == types.SeverityInfo
}

// GetSeverity returns the customized severity for a policy
func (c *SeverityConfig) GetSeverity(policyID string, originalSeverity string) string {
	// First check for a custom severity
	if severity, ok := c.Severities[policyID]; ok {
		return severity
	}

	// If the original severity is valid, return it
	originalSeverity = strings.ToLower(originalSeverity)
	if isValidSeverity(originalSeverity) {
		return originalSeverity
	}

	// Fall back to default severity
	return c.DefaultSeverity
}