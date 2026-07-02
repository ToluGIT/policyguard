# Azure Storage Account security policies.
#
# Azure-specific domain notes (these drive when we do and do NOT flag):
#   * HTTPS-only is the default. The attribute was renamed across azurerm
#     versions: v3 used `enable_https_traffic_only`, v4 uses
#     `https_traffic_only_enabled`. We check BOTH and only flag an EXPLICIT
#     false — an absent attribute defaults to secure, so absence is NOT a
#     finding (flagging absence here would be a false positive).
#   * min_tls_version defaults to TLS1_2. We flag only an explicit weak version
#     (TLS1_0 / TLS1_1), never absence.
#   * Public blob access (allow_nested_items_to_be_public) defaults to false in
#     azurerm v4; we flag an explicit true.
package policyguard

import future.keywords.contains
import future.keywords.if

# Deny storage accounts that explicitly disable HTTPS-only traffic.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_storage_account"

	https_only_explicitly_disabled(resource)

	violation := {
		"id": sprintf("azure-storage-no-https-%s", [resource.name]),
		"policy_id": "azure_storage_https_only",
		"severity": "high",
		"message": sprintf("Azure storage account '%s' allows non-HTTPS (HTTP) traffic", [resource.name]),
		"details": "Storage accounts should require HTTPS for all traffic to protect data in transit",
		"remediation": "Set https_traffic_only_enabled = true (azurerm v4) or enable_https_traffic_only = true (azurerm v3)",
	}
}

# Deny storage accounts with a weak minimum TLS version explicitly set.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_storage_account"

	weak_tls(resource.attributes.min_tls_version)

	violation := {
		"id": sprintf("azure-storage-weak-tls-%s", [resource.name]),
		"policy_id": "azure_storage_min_tls",
		"severity": "medium",
		"message": sprintf("Azure storage account '%s' allows a weak minimum TLS version (%s)", [resource.name, resource.attributes.min_tls_version]),
		"details": "Storage accounts should require TLS 1.2 or higher",
		"remediation": "Set min_tls_version = \"TLS1_2\"",
	}
}

# Deny storage accounts that explicitly allow public blob/container access.
deny[violation] {
	resource := input.resource
	resource.type == "azurerm_storage_account"

	resource.attributes.allow_nested_items_to_be_public == true

	violation := {
		"id": sprintf("azure-storage-public-access-%s", [resource.name]),
		"policy_id": "azure_storage_public_access",
		"severity": "high",
		"message": sprintf("Azure storage account '%s' allows public access to blobs/containers", [resource.name]),
		"details": "Public blob access exposes stored objects to anonymous readers",
		"remediation": "Set allow_nested_items_to_be_public = false",
	}
}

# https_only_explicitly_disabled is true only when one of the HTTPS-only
# attributes (either azurerm version's spelling) is explicitly set to false.
https_only_explicitly_disabled(resource) if {
	resource.attributes.https_traffic_only_enabled == false
}

https_only_explicitly_disabled(resource) if {
	resource.attributes.enable_https_traffic_only == false
}

# weak_tls is true for the deprecated TLS versions only.
weak_tls("TLS1_0")
weak_tls("TLS1_1")
