# Benchmark fixture: Azure resources configured securely. A correct policy set
# must produce ZERO findings here (these are the true negatives). This exercises:
#   * the azurerm v4 attribute name (https_traffic_only_enabled),
#   * reliance on Azure's secure-by-default values (the "defaults" account sets
#     no security attributes and must NOT be flagged), and
#   * a multi-rule NSG (list shape) where admin access is restricted to a CIDR.

resource "azurerm_storage_account" "secure" {
  name                            = "benchsecuresa"
  https_traffic_only_enabled      = true # v4 spelling
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_account" "secure_defaults" {
  name = "benchdefaultsa"
  # No security attributes set: HTTPS-only and TLS1_2 are the Azure defaults,
  # and public access defaults to false. Must not be flagged.
}

resource "azurerm_network_security_group" "secure" {
  name = "bench-secure-nsg"

  security_rule {
    name                   = "ssh-internal-only"
    priority               = 100
    direction              = "Inbound"
    access                 = "Allow"
    protocol               = "Tcp"
    destination_port_range = "22"
    source_address_prefix  = "10.0.0.0/16" # restricted, not the internet
  }

  security_rule {
    name                   = "https-public"
    priority               = 110
    direction              = "Inbound"
    access                 = "Allow"
    protocol               = "Tcp"
    destination_port_range = "443" # not an admin port
    source_address_prefix  = "*"
  }
}

resource "azurerm_mssql_server" "secure" {
  name                          = "bench-secure-sql"
  version                       = "12.0"
  public_network_access_enabled = false
  minimum_tls_version           = "1.2"
}
