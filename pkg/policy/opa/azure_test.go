package opa

import (
	"context"
	"testing"

	"github.com/ToluGIT/policyguard/pkg/types"
)

func loadAzureEngine(t *testing.T) *Engine {
	t.Helper()
	e := New()
	ctx := context.Background()
	for _, p := range []string{
		"../../../policies/azure/storage_account_security.rego",
		"../../../policies/azure/network_security.rego",
		"../../../policies/azure/sql_security.rego",
	} {
		if err := e.LoadPolicy(ctx, p); err != nil {
			t.Fatalf("load %s: %v", p, err)
		}
	}
	return e
}

func policyIDs(violations []types.PolicyViolation) map[string]bool {
	out := map[string]bool{}
	for _, v := range violations {
		out[v.PolicyID] = true
	}
	return out
}

// TestAzure_StorageHTTPSBothAttributeNames verifies the policy flags the v3
// attribute name (enable_https_traffic_only=false) and does NOT flag the v4
// secure value (https_traffic_only_enabled=true) or an absent attribute (Azure
// defaults to HTTPS-only).
func TestAzure_StorageHTTPSBothAttributeNames(t *testing.T) {
	e := loadAzureEngine(t)

	cases := []struct {
		name      string
		attrs     map[string]interface{}
		wantHTTPS bool // expect azure_storage_https_only to fire
	}{
		{"v3 explicit false", map[string]interface{}{"enable_https_traffic_only": false}, true},
		{"v4 explicit false", map[string]interface{}{"https_traffic_only_enabled": false}, true},
		{"v4 secure true", map[string]interface{}{"https_traffic_only_enabled": true}, false},
		{"absent (secure default)", map[string]interface{}{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := e.Evaluate(context.Background(), []types.Resource{
				{ID: "azurerm_storage_account.s", Type: "azurerm_storage_account", Name: "s", Attributes: c.attrs},
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := policyIDs(res.Violations)["azure_storage_https_only"]
			if got != c.wantHTTPS {
				t.Errorf("azure_storage_https_only fired=%v, want %v (attrs=%v)", got, c.wantHTTPS, c.attrs)
			}
		})
	}
}

// TestAzure_NSGSingleAndListRuleShapes verifies the NSG policy handles both the
// single-rule (object) and multi-rule (list) parser shapes, and only flags
// internet-exposed admin ports.
func TestAzure_NSGSingleAndListRuleShapes(t *testing.T) {
	e := loadAzureEngine(t)
	open := map[string]interface{}{
		"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
		"destination_port_range": "22", "source_address_prefix": "*",
	}
	restricted := map[string]interface{}{
		"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
		"destination_port_range": "22", "source_address_prefix": "10.0.0.0/16",
	}

	// Single rule (object shape), exposed -> fires.
	res, _ := e.Evaluate(context.Background(), []types.Resource{
		{ID: "azurerm_network_security_group.a", Type: "azurerm_network_security_group", Name: "a",
			Attributes: map[string]interface{}{"security_rule": open}},
	})
	if !policyIDs(res.Violations)["azure_nsg_admin_ports"] {
		t.Error("single open rule (object shape) should fire azure_nsg_admin_ports")
	}

	// Multiple rules (list shape), one exposed -> fires.
	res, _ = e.Evaluate(context.Background(), []types.Resource{
		{ID: "azurerm_network_security_group.b", Type: "azurerm_network_security_group", Name: "b",
			Attributes: map[string]interface{}{"security_rule": []interface{}{restricted, open}}},
	})
	if !policyIDs(res.Violations)["azure_nsg_admin_ports"] {
		t.Error("list with one open rule should fire azure_nsg_admin_ports")
	}

	// Restricted only (list shape) -> must NOT fire.
	res, _ = e.Evaluate(context.Background(), []types.Resource{
		{ID: "azurerm_network_security_group.c", Type: "azurerm_network_security_group", Name: "c",
			Attributes: map[string]interface{}{"security_rule": []interface{}{restricted}}},
	})
	if policyIDs(res.Violations)["azure_nsg_admin_ports"] {
		t.Error("restricted-CIDR rule should NOT fire azure_nsg_admin_ports (false positive)")
	}
}

// TestAzure_NSGPluralPortAndSourceForms guards against a false negative: azurerm
// rules can use the plural list forms destination_port_ranges and
// source_address_prefixes. A rule exposing an admin port to the internet via
// those plural forms must still be flagged, while a plural-form rule restricted
// to a private CIDR must not.
func TestAzure_NSGPluralPortAndSourceForms(t *testing.T) {
	e := loadAzureEngine(t)

	exposed := map[string]interface{}{
		"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
		"destination_port_ranges": []interface{}{"22", "3389"},
		"source_address_prefixes": []interface{}{"0.0.0.0/0"},
	}
	restricted := map[string]interface{}{
		"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
		"destination_port_ranges": []interface{}{"22"},
		"source_address_prefixes": []interface{}{"10.0.0.0/16"},
	}

	res, _ := e.Evaluate(context.Background(), []types.Resource{
		{ID: "azurerm_network_security_group.p", Type: "azurerm_network_security_group", Name: "p",
			Attributes: map[string]interface{}{"security_rule": exposed}},
	})
	if !policyIDs(res.Violations)["azure_nsg_admin_ports"] {
		t.Error("plural-form internet exposure should fire azure_nsg_admin_ports (false negative)")
	}

	res, _ = e.Evaluate(context.Background(), []types.Resource{
		{ID: "azurerm_network_security_group.q", Type: "azurerm_network_security_group", Name: "q",
			Attributes: map[string]interface{}{"security_rule": restricted}},
	})
	if policyIDs(res.Violations)["azure_nsg_admin_ports"] {
		t.Error("plural-form restricted rule should NOT fire (false positive)")
	}
}

// TestAzure_SQLAndStorageSecureDefaults is the true-negative guard: a SQL server
// and storage account with secure explicit values produce no findings.
func TestAzure_SQLAndStorageSecureDefaults(t *testing.T) {
	e := loadAzureEngine(t)
	res, err := e.Evaluate(context.Background(), []types.Resource{
		{ID: "azurerm_mssql_server.s", Type: "azurerm_mssql_server", Name: "s",
			Attributes: map[string]interface{}{"public_network_access_enabled": false, "minimum_tls_version": "1.2"}},
		{ID: "azurerm_storage_account.s", Type: "azurerm_storage_account", Name: "s",
			Attributes: map[string]interface{}{"https_traffic_only_enabled": true, "min_tls_version": "TLS1_2", "allow_nested_items_to_be_public": false}},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if n := len(res.Violations); n != 0 {
		t.Errorf("secure Azure config produced %d findings, want 0: %+v", n, res.Violations)
	}
}
