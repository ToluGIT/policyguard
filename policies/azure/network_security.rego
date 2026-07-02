# Azure Network Security Group policies.
#
# Azure-specific domain notes:
#   * Rules can be declared two ways: inline `security_rule {}` blocks on an
#     azurerm_network_security_group, or standalone azurerm_network_security_rule
#     resources. We handle both.
#   * The HCL parser collapses a single inline `security_rule {}` block into one
#     object and multiple blocks into a list. normalize_rules() coerces either
#     shape into a list so the rule logic is uniform (a single object iterated
#     directly in Rego would misbehave).
#   * "From the internet" in Azure is any of "*", "0.0.0.0/0", or the service
#     tag "Internet" as the source_address_prefix.
package policyguard

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny NSGs with an inline rule exposing SSH or RDP to the internet.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_network_security_group"

	some rule in normalize_rules(resource.attributes.security_rule)
	rule_exposes_admin_port(rule)

	violation := {
		"id": sprintf("azure-nsg-admin-port-open-%s", [resource.name]),
		"policy_id": "azure_nsg_admin_ports",
		"severity": "critical",
		"message": sprintf("Azure NSG '%s' allows SSH/RDP access from the internet", [resource.name]),
		"details": "Security groups should not allow inbound SSH (22) or RDP (3389) from the internet",
		"remediation": "Restrict source_address_prefix to specific IP ranges, or use Azure Bastion for administrative access",
	}
}

# Deny standalone NSG rules exposing SSH or RDP to the internet.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_network_security_rule"

	rule_exposes_admin_port(resource.attributes)

	violation := {
		"id": sprintf("azure-nsg-rule-admin-port-open-%s", [resource.name]),
		"policy_id": "azure_nsg_admin_ports",
		"severity": "critical",
		"message": sprintf("Azure NSG rule '%s' allows SSH/RDP access from the internet", [resource.name]),
		"details": "Security group rules should not allow inbound SSH (22) or RDP (3389) from the internet",
		"remediation": "Restrict source_address_prefix to specific IP ranges, or use Azure Bastion for administrative access",
	}
}

# normalize_rules coerces the parser's single-object-or-list shape into a list.
normalize_rules(rules) := rules if {
	is_array(rules)
}

normalize_rules(rules) := [rules] if {
	is_object(rules)
}

normalize_rules(rules) := [] if {
	not is_array(rules)
	not is_object(rules)
}

# rule_exposes_admin_port is true for an inbound Allow rule that opens SSH or RDP
# from an internet-equivalent source. Both the singular and plural azurerm forms
# of the source and destination fields are checked — destination_port_range /
# destination_port_ranges and source_address_prefix / source_address_prefixes —
# because either form is valid HCL and checking only the singular form would
# silently miss a rule written with the list form (a false negative).
rule_exposes_admin_port(rule) if {
	lower(rule.direction) == "inbound"
	lower(rule.access) == "allow"
	rule_source_is_internet(rule)
	rule_targets_admin_port(rule)
}

# --- source: singular prefix or plural prefixes ---
rule_source_is_internet(rule) if {
	internet_source(rule.source_address_prefix)
}

rule_source_is_internet(rule) if {
	some p in rule.source_address_prefixes
	internet_source(p)
}

internet_source("*")
internet_source("0.0.0.0/0")
internet_source("Internet")

# --- destination: singular range or plural ranges ---
rule_targets_admin_port(rule) if {
	port_value_hits_admin(rule.destination_port_range)
}

rule_targets_admin_port(rule) if {
	some pr in rule.destination_port_ranges
	port_value_hits_admin(pr)
}

# port_value_hits_admin matches an admin port as an exact value, a "*" wildcard,
# or within a "from-to" range.
port_value_hits_admin(value) if {
	value == admin_port[_]
}

port_value_hits_admin("*")

port_value_hits_admin(value) if {
	port := admin_port[_]
	port_in_range(value, port)
}

admin_port := ["22", "3389"]

# port_in_range reports whether portStr (e.g. "20-30") includes target (e.g. "22").
port_in_range(rangeStr, target) if {
	parts := split(rangeStr, "-")
	count(parts) == 2
	low := to_number(parts[0])
	high := to_number(parts[1])
	t := to_number(target)
	low <= t
	t <= high
}
