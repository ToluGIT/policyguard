package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// SuppressionConfig is a set of rules that acknowledge specific findings without
// removing the policy that produces them. Suppressing is deliberately auditable:
// every rule must carry a reason, and rules may expire so a suppression cannot
// quietly live forever. This is the antidote to the usual escape hatch (deleting
// or disabling the policy), which loses the signal entirely.
type SuppressionConfig struct {
	Description string            `json:"description"`
	Rules       []SuppressionRule `json:"rules"`
}

// SuppressionRule acknowledges findings for a policy, optionally narrowed to a
// specific resource. Reason is mandatory; Expires (YYYY-MM-DD) is optional.
type SuppressionRule struct {
	PolicyID string `json:"policy_id"`
	// Resource optionally narrows the rule to one resource ID
	// (e.g. "aws_s3_bucket.public_site"). Empty means all resources for the
	// policy.
	Resource string `json:"resource,omitempty"`
	Reason   string `json:"reason"`
	// Expires is an optional date (YYYY-MM-DD) after which the rule no longer
	// applies, so stale suppressions resurface instead of hiding findings forever.
	Expires string `json:"expires,omitempty"`
}

// NewEmptySuppressionConfig returns a config that suppresses nothing.
func NewEmptySuppressionConfig() *SuppressionConfig {
	return &SuppressionConfig{Rules: []SuppressionRule{}}
}

// LoadSuppressionConfig reads and validates a suppression config from disk.
// It fails if any rule lacks a policy_id or reason, or carries an unparseable
// expiry — a malformed suppression file should be a loud error, never a silent
// "suppress nothing" (or worse, "suppress everything").
func LoadSuppressionConfig(configPath string) (*SuppressionConfig, error) {
	if configPath == "" {
		return NewEmptySuppressionConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read suppression configuration: %w", err)
	}

	var cfg SuppressionConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse suppression configuration: %w", err)
	}

	for i, r := range cfg.Rules {
		if r.PolicyID == "" {
			return nil, fmt.Errorf("suppression rule %d is missing policy_id", i)
		}
		if r.Reason == "" {
			return nil, fmt.Errorf("suppression rule %d (%s) is missing a reason; suppressions must be justified", i, r.PolicyID)
		}
		if r.Expires != "" {
			if _, err := time.Parse("2006-01-02", r.Expires); err != nil {
				return nil, fmt.Errorf("suppression rule %d (%s) has invalid expires %q (want YYYY-MM-DD): %w", i, r.PolicyID, r.Expires, err)
			}
		}
	}

	return &cfg, nil
}

// Match returns the first active rule that suppresses the given violation, and
// true, or (zero, false) if none applies. A rule matches when its policy_id
// equals the violation's, its resource (if set) equals the violation's resource,
// and it has not expired as of now.
func (c *SuppressionConfig) Match(v types.PolicyViolation, now time.Time) (SuppressionRule, bool) {
	if c == nil {
		return SuppressionRule{}, false
	}
	for _, r := range c.Rules {
		if r.PolicyID != v.PolicyID {
			continue
		}
		if r.Resource != "" && r.Resource != v.ResourceID {
			continue
		}
		if r.expired(now) {
			continue
		}
		return r, true
	}
	return SuppressionRule{}, false
}

// expired reports whether the rule's expiry date is strictly before now's date.
// A rule with no expiry never expires. Comparison is date-granular.
func (r SuppressionRule) expired(now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	exp, err := time.Parse("2006-01-02", r.Expires)
	if err != nil {
		// Validated at load time; treat an unparseable value defensively as
		// not-expired so we never accidentally suppress on a bad date.
		return false
	}
	// Expired once the current date is past the expiry day.
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return today.After(exp)
}
