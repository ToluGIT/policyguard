# Benchmark fixture: Azure resources with explicit, unambiguous misconfigurations.
# Values are synthetic. Ground truth is in labels.json.
#
# SME judgment: each finding below is a genuine misconfiguration a knowledgeable
# Azure reviewer would flag. The storage account uses the azurerm v3 attribute
# name (enable_https_traffic_only) to exercise version handling.

resource "azurerm_storage_account" "exposed" {
  name                            = "benchexposedsa"
  enable_https_traffic_only       = false    # v3 spelling -> azure_storage_https_only
  min_tls_version                 = "TLS1_0" # -> azure_storage_min_tls
  allow_nested_items_to_be_public = true     # -> azure_storage_public_access
}

resource "azurerm_network_security_group" "exposed" {
  name = "bench-exposed-nsg"
  security_rule {
    name                       = "allow-ssh-world"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    destination_port_range     = "22"
    source_address_prefix      = "*" # -> azure_nsg_admin_ports
    destination_address_prefix = "*"
  }
}

resource "azurerm_mssql_server" "exposed" {
  name                          = "bench-exposed-sql"
  version                       = "12.0"
  public_network_access_enabled = true  # -> azure_sql_public_access
  minimum_tls_version           = "1.0" # -> azure_sql_min_tls
}
