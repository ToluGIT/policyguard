package opa

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestSiblingResourceTypes_CoversAllPolicyLookups guards the performance/
// correctness coupling introduced by filtering input.all_resources: only
// resource types in siblingResourceTypes are exposed to policies as siblings.
// If a policy adds a `sibling.type == "X"` lookup for a type NOT in that set,
// the lookup silently never matches — a false negative. This test extracts every
// sibling type referenced across the policy files and asserts each is registered
// in siblingResourceTypes, so the two cannot drift apart unnoticed.
func TestSiblingResourceTypes_CoversAllPolicyLookups(t *testing.T) {
	policyDir := "../../../policies"
	re := regexp.MustCompile(`sibling\.type\s*==\s*"([a-zA-Z0-9_]+)"`)

	referenced := map[string]string{} // type -> file where referenced
	err := filepath.Walk(policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".rego" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			referenced[m[1]] = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking policies: %v", err)
	}

	if len(referenced) == 0 {
		t.Skip("no sibling.type lookups found in policies")
	}

	for typ, file := range referenced {
		if !siblingResourceTypes[typ] {
			t.Errorf("policy %s looks up sibling type %q, but it is not in siblingResourceTypes "+
				"(engine.go) — input.all_resources will not contain it, so the lookup silently "+
				"never matches (false negative). Add %q to siblingResourceTypes.", file, typ, typ)
		}
	}
}
