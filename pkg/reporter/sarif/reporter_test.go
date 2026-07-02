package sarif

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// sample builds a report with two findings: one whose policy is CWE-mapped and
// one that is not, so tests can assert both the mapped and unmapped paths.
func sample() *types.Report {
	return &types.Report{
		Violations: []types.PolicyViolation{
			{
				ID:          "s3-no-encryption-b1",
				ResourceID:  "aws_s3_bucket.b1",
				PolicyID:    "s3_bucket_encryption", // mapped -> CWE-311
				Severity:    "high",
				Message:     "bucket b1 is not encrypted",
				Details:     "encrypt at rest",
				Remediation: "add encryption",
				Location:    types.Location{File: "main.tf", Line: 3, Column: 1},
			},
			{
				ID:         "rds-no-iam-auth-db1",
				ResourceID: "aws_db_instance.db1",
				PolicyID:   "rds_iam_authentication", // intentionally unmapped
				Severity:   "low",
				Message:    "db1 lacks IAM auth",
				Location:   types.Location{File: "main.tf", Line: 9, Column: 1},
			},
		},
	}
}

func render(t *testing.T, r *Reporter, report *types.Report) map[string]interface{} {
	t.Helper()
	var buf bytes.Buffer
	if err := r.Write(context.Background(), report, &buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	return out
}

func firstRun(t *testing.T, out map[string]interface{}) map[string]interface{} {
	t.Helper()
	runs, ok := out["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("no runs in SARIF output")
	}
	return runs[0].(map[string]interface{})
}

func TestSARIF_VersionThreadedThrough(t *testing.T) {
	out := render(t, NewWithVersion("9.9.9"), sample())
	driver := firstRun(t, out)["tool"].(map[string]interface{})["driver"].(map[string]interface{})

	if got := driver["version"]; got != "9.9.9" {
		t.Errorf("driver version = %v, want 9.9.9", got)
	}
	if got := driver["semanticVersion"]; got != "9.9.9" {
		t.Errorf("semanticVersion = %v, want 9.9.9", got)
	}
	// The old hardcoded value must never reappear.
	if strings.Contains(driver["version"].(string), "1.0.0") {
		t.Error("driver version still hardcoded to 1.0.0")
	}
}

func TestSARIF_CWETagsForMappedPolicy(t *testing.T) {
	out := render(t, New(), sample())
	rules := firstRun(t, out)["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})

	var encRule map[string]interface{}
	for _, ri := range rules {
		r := ri.(map[string]interface{})
		if r["id"] == "s3_bucket_encryption" {
			encRule = r
		}
	}
	if encRule == nil {
		t.Fatal("s3_bucket_encryption rule missing")
	}

	props := encRule["properties"].(map[string]interface{})
	cwe, ok := props["cwe"].([]interface{})
	if !ok || len(cwe) == 0 {
		t.Fatalf("expected cwe property on mapped rule, got %v", props["cwe"])
	}
	if cwe[0] != "CWE-311" {
		t.Errorf("cwe = %v, want CWE-311", cwe[0])
	}

	tags := props["tags"].([]interface{})
	if !containsStr(tags, "external/cwe/cwe-311") {
		t.Errorf("tags missing external/cwe/cwe-311: %v", tags)
	}
}

func TestSARIF_NoCWEForUnmappedPolicy(t *testing.T) {
	out := render(t, New(), sample())
	rules := firstRun(t, out)["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})

	for _, ri := range rules {
		r := ri.(map[string]interface{})
		if r["id"] == "rds_iam_authentication" {
			props := r["properties"].(map[string]interface{})
			if _, exists := props["cwe"]; exists {
				t.Errorf("unmapped policy should not carry a guessed cwe, got %v", props["cwe"])
			}
			return
		}
	}
	t.Fatal("rds_iam_authentication rule missing")
}

func TestSARIF_PartialFingerprintsPresentAndStable(t *testing.T) {
	out1 := render(t, New(), sample())
	out2 := render(t, New(), sample())

	fps := func(out map[string]interface{}) []string {
		results := firstRun(t, out)["results"].([]interface{})
		var got []string
		for _, ri := range results {
			r := ri.(map[string]interface{})
			pf, ok := r["partialFingerprints"].(map[string]interface{})
			if !ok {
				t.Fatalf("result missing partialFingerprints: %v", r)
			}
			fp, ok := pf["policyguardFindingV1"].(string)
			if !ok || fp == "" {
				t.Fatalf("missing policyguardFindingV1 fingerprint: %v", pf)
			}
			got = append(got, fp)
		}
		return got
	}

	a, b := fps(out1), fps(out2)
	if len(a) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("fingerprint not stable across runs: %s != %s", a[i], b[i])
		}
	}
	if a[0] == a[1] {
		t.Error("distinct findings produced identical fingerprints")
	}
}

func TestSARIF_RuleIndexResolvesToRuleID(t *testing.T) {
	out := render(t, New(), sample())
	run := firstRun(t, out)
	rules := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})
	results := run["results"].([]interface{})

	for _, ri := range results {
		r := ri.(map[string]interface{})
		idx := int(r["ruleIndex"].(float64))
		if idx < 0 || idx >= len(rules) {
			t.Fatalf("ruleIndex %d out of range (%d rules)", idx, len(rules))
		}
		ruleID := rules[idx].(map[string]interface{})["id"]
		if ruleID != r["ruleId"] {
			t.Errorf("ruleIndex %d points at rule %v, but result ruleId is %v", idx, ruleID, r["ruleId"])
		}
	}
}

func TestSARIF_NewUsesDevPlaceholderNotRealVersion(t *testing.T) {
	out := render(t, New(), sample())
	driver := firstRun(t, out)["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	if got := driver["version"].(string); got != defaultVersion {
		t.Errorf("New() version = %q, want placeholder %q", got, defaultVersion)
	}
}

// TestSARIF_NoFingerprintCollisionSamePolicySameResource guards the case where
// one policy has multiple deny rules that can all fire on a single resource
// (e.g. a security group that is both SSH-open and all-traffic-open). Those are
// distinct findings and must get distinct fingerprints, or code scanning would
// dedupe them into one and silently drop a real finding.
func TestSARIF_NoFingerprintCollisionSamePolicySameResource(t *testing.T) {
	report := &types.Report{
		Violations: []types.PolicyViolation{
			{
				ID:         "sg-ssh-open-multi",
				ResourceID: "aws_security_group.multi",
				PolicyID:   "security_group_ssh_open",
				Severity:   "critical",
				Message:    "SSH open",
				Location:   types.Location{File: "main.tf", Line: 3, Column: 1},
			},
			{
				ID:         "sg-ssh-open-all-multi",
				ResourceID: "aws_security_group.multi",
				PolicyID:   "security_group_ssh_open", // same policy + resource, different finding
				Severity:   "critical",
				Message:    "all traffic open",
				Location:   types.Location{File: "main.tf", Line: 3, Column: 1},
			},
		},
	}

	out := render(t, New(), report)
	results := firstRun(t, out)["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	fp0 := results[0].(map[string]interface{})["partialFingerprints"].(map[string]interface{})["policyguardFindingV1"]
	fp1 := results[1].(map[string]interface{})["partialFingerprints"].(map[string]interface{})["policyguardFindingV1"]
	if fp0 == fp1 {
		t.Errorf("distinct findings of the same policy on the same resource collided: %v", fp0)
	}
}

func containsStr(list []interface{}, want string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
