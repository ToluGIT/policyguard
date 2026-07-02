# Azure SQL (Microsoft SQL Server) security policies.
#
# Azure-specific domain notes:
#   * public_network_access_enabled defaults to TRUE on azurerm_mssql_server, so
#     a publicly-reachable server is the default. We flag an EXPLICIT true (an
#     unambiguous, intentional public exposure). We do not flag absence: while
#     the default is public, an omitted attribute is commonly paired with other
#     network controls, and asserting a violation on absence here would generate
#     false positives — a documented limitation, mirroring the honest stance
#     taken elsewhere (see the IMDSv2 absent-block case).
#   * minimum_tls_version defaults to "1.2"; we flag only an explicit weak value.
package policyguard

import future.keywords.contains
import future.keywords.if

# Deny SQL servers that explicitly enable public network access.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_mssql_server"

	resource.attributes.public_network_access_enabled == true

	violation := {
		"id": sprintf("azure-sql-public-access-%s", [resource.name]),
		"policy_id": "azure_sql_public_access",
		"severity": "high",
		"message": sprintf("Azure SQL server '%s' is reachable from public networks", [resource.name]),
		"details": "SQL servers should not be exposed to public networks; use private endpoints or firewall restrictions",
		"remediation": "Set public_network_access_enabled = false and use a private endpoint",
	}
}

# Deny SQL servers with a weak minimum TLS version explicitly set.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_mssql_server"

	weak_sql_tls(resource.attributes.minimum_tls_version)

	violation := {
		"id": sprintf("azure-sql-weak-tls-%s", [resource.name]),
		"policy_id": "azure_sql_min_tls",
		"severity": "medium",
		"message": sprintf("Azure SQL server '%s' allows a weak minimum TLS version (%s)", [resource.name, resource.attributes.minimum_tls_version]),
		"details": "SQL servers should require TLS 1.2 or higher",
		"remediation": "Set minimum_tls_version = \"1.2\"",
	}
}

weak_sql_tls("1.0")
weak_sql_tls("1.1")
