package compliance

import "testing"

func TestCWEsFor_MappedPolicy(t *testing.T) {
	cwes := CWEsFor("s3_bucket_encryption")
	if len(cwes) != 1 || cwes[0] != "CWE-311" {
		t.Errorf("s3_bucket_encryption CWEs = %v, want [CWE-311]", cwes)
	}
}

func TestCWEsFor_UnmappedPolicyReturnsNil(t *testing.T) {
	// An unmapped policy must return nothing, never a guessed CWE.
	if cwes := CWEsFor("rds_iam_authentication"); cwes != nil {
		t.Errorf("unmapped policy returned %v, want nil", cwes)
	}
	if _, ok := For("totally_unknown_policy"); ok {
		t.Error("For() reported a mapping for an unknown policy")
	}
}

func TestMappings_EveryCWEHasTitle(t *testing.T) {
	// A mapped CWE without a title would produce a misaligned cwe_title column
	// in the compliance report (e.g. ";Improper Access Control"). Guard it.
	for id, m := range mappings {
		for _, cwe := range m.CWE {
			if CWETitle(cwe) == "" {
				t.Errorf("policy %q maps to %q which has no CWETitle entry", id, cwe)
			}
		}
	}
}

func TestMappings_AllCWEsWellFormed(t *testing.T) {
	// Guard against a malformed entry (e.g. "311" instead of "CWE-311").
	for id, m := range mappings {
		for _, cwe := range m.CWE {
			if len(cwe) < 5 || cwe[:4] != "CWE-" {
				t.Errorf("policy %q has malformed CWE %q (want CWE-NNN form)", id, cwe)
			}
		}
	}
}
