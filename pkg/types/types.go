package types

import (
	"time"
)

// Resource represents a parsed infrastructure resource
type Resource struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Provider   string                 `json:"provider"`
	Name       string                 `json:"name"`
	Attributes map[string]interface{} `json:"attributes"`
	Location   Location               `json:"location"`
}

// Location represents the source location of a resource
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// PolicyViolation represents a security policy violation
type PolicyViolation struct {
	ID          string    `json:"id"`
	ResourceID  string    `json:"resource_id"`
	PolicyID    string    `json:"policy_id"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Details     string    `json:"details"`
	Remediation string    `json:"remediation"`
	Location    Location  `json:"location"`
	Timestamp   time.Time `json:"timestamp"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Passed     bool                   `json:"passed"`
	Violations []PolicyViolation      `json:"violations"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// Report represents the final analysis report
type Report struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Summary    Summary                `json:"summary"`
	Violations []PolicyViolation      `json:"violations"`
	Resources  []Resource             `json:"resources"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// Summary represents report summary statistics
type Summary struct {
	TotalResources   int            `json:"total_resources"`
	TotalViolations  int            `json:"total_violations"`
	ViolationsBySeverity map[string]int `json:"violations_by_severity"`
	PassRate         float64        `json:"pass_rate"`
}

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)