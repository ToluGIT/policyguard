package policyguard

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed all:policies
var policiesFS embed.FS

// GetEmbeddedPolicies returns a map of policy name to content from embedded files
func GetEmbeddedPolicies() (map[string]string, error) {
	policies := make(map[string]string)
	
	err := fs.WalkDir(policiesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories and non-.rego files
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		
		// Read policy content
		content, err := policiesFS.ReadFile(path)
		if err != nil {
			return err
		}
		
		// Use relative path as key
		policies[path] = string(content)
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return policies, nil
}

// HasEmbeddedPolicies checks if embedded policies are available
func HasEmbeddedPolicies() bool {
	_, err := policiesFS.ReadDir("policies")
	return err == nil
}