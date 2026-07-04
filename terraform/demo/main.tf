##############################################################################
# Demo Infrastructure — INTENTIONALLY NON-COMPLIANT
#
# This configuration exists solely to demonstrate policy violations.
# Do NOT use it as a reference for production Terraform.
##############################################################################

# ---------------------------------------------------------------------------
# Resource Group — ❌ VIOLATION: Missing required tags (owner, cost-centre)
#                  ❌ VIOLATION: Name does not follow convention (uppercase)
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "demo" {
  name     = "DemoResourceGroup"   # ← naming violation (uppercase)
  location = var.location

  tags = {
    env     = "dev"
    project = "demo"
    # Missing: owner, cost-centre
  }
}

# ---------------------------------------------------------------------------
# Storage Account — ❌ VIOLATION: Public network access enabled
#                   ❌ VIOLATION: Missing required tags
#                   ❌ VIOLATION: Naming convention (should start with 'st')
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "demo" {
  name                          = "demopublicstorage123"  # ← naming violation
  resource_group_name           = azurerm_resource_group.demo.name
  location                      = azurerm_resource_group.demo.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"

  # ❌ Public access explicitly enabled
  public_network_access_enabled = true
  allow_nested_items_to_be_public = true

  network_rules {
    default_action = "Allow"   # ← allows all traffic
  }

  tags = {
    project = "demo"
    # Missing: owner, env, cost-centre
  }
}

# ---------------------------------------------------------------------------
# Network Security Group — used to attach the open SSH rule
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "demo" {
  name                = "nsg-demo"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  tags = {
    owner       = "demo-team"
    env         = "dev"
    project     = "demo"
    cost-centre = "CC-000"
  }
}

# ---------------------------------------------------------------------------
# NSG Rule — ❌ VIOLATION: Allows SSH (port 22) from 0.0.0.0/0
# ---------------------------------------------------------------------------
resource "azurerm_network_security_rule" "allow_ssh" {
  name                        = "AllowSSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "0.0.0.0/0"   # ← open to the world
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.demo.name
  network_security_group_name = azurerm_network_security_group.demo.name
}

# ---------------------------------------------------------------------------
# Managed Disk — ❌ VIOLATION: No encryption specified
#                ❌ VIOLATION: Missing required tags
#                ❌ VIOLATION: Naming convention
# ---------------------------------------------------------------------------
resource "azurerm_managed_disk" "demo" {
  name                 = "MyDemoDisk"          # ← naming violation
  location             = azurerm_resource_group.demo.location
  resource_group_name  = azurerm_resource_group.demo.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 10

  # ❌ No encryption_settings or disk_encryption_set_id

  tags = {
    env = "dev"
    # Missing: owner, project, cost-centre
  }
}

# ---------------------------------------------------------------------------
# Virtual Network — ❌ VIOLATION: Missing required tags
#                   ❌ VIOLATION: Naming convention (should start with 'vnet-')
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "demo" {
  name                = "MyVNET"               # ← naming violation
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  address_space       = ["10.0.0.0/16"]

  # No tags at all
}

# ---------------------------------------------------------------------------
# MSSQL Server & Firewall Rule — ❌ VIOLATION: SQL_FIREWALL_OPEN (0.0.0.0)
# ---------------------------------------------------------------------------
resource "azurerm_mssql_server" "demo" {
  name                         = "sqlpolicydemo123"
  resource_group_name          = azurerm_resource_group.demo.name
  location                     = azurerm_resource_group.demo.location
  version                      = "12.0"
  administrator_login          = "sqladminuser"
  administrator_login_password = "P@ssw0rd123456!"

  tags = {
    owner       = "demo-team"
    env         = "dev"
    project     = "demo"
    cost-centre = "CC-000"
  }
}

resource "azurerm_mssql_firewall_rule" "open_sql" {
  name             = "AllowAll"
  server_id        = azurerm_mssql_server.demo.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# ---------------------------------------------------------------------------
# App Service Plan & Linux Web App — ❌ VIOLATION: HTTPS_ONLY
# ---------------------------------------------------------------------------
resource "azurerm_service_plan" "demo" {
  name                = "asp-demo"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  os_type             = "Linux"
  sku_name            = "B1"

  tags = {
    owner       = "demo-team"
    env         = "dev"
    project     = "demo"
    cost-centre = "CC-000"
  }
}

resource "azurerm_linux_web_app" "non_https" {
  name                = "policy-demo-webapp-12345"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  service_plan_id     = azurerm_service_plan.demo.id
  https_only          = false

  site_config {}

  tags = {
    owner       = "demo-team"
    env         = "dev"
    project     = "demo"
    cost-centre = "CC-000"
  }
}
