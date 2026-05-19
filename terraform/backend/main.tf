##############################################################################
# Azure Policy Gate — Backend Infrastructure
# Provisions the Storage Account used for:
#   1. Terraform remote state (blob container)
#   2. Policy violation audit log (Table Storage)
##############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

provider "azurerm" {
  features {}
}

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "policy_gate" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    project    = "azure-policy-gate"
    owner      = var.owner
    env        = "shared"
    cost-centre = var.cost_centre
    managed-by = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Storage Account — remote state + violation log
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "tfstate" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.policy_gate.name
  location                 = azurerm_resource_group.policy_gate.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Best-practice: disable public blob access for the state backend
  allow_nested_items_to_be_public = false

  tags = azurerm_resource_group.policy_gate.tags
}

# ---------------------------------------------------------------------------
# Blob Container — Terraform remote state
# ---------------------------------------------------------------------------
resource "azurerm_storage_container" "tfstate" {
  name                  = "tfstate"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}

# ---------------------------------------------------------------------------
# Table — Policy Violations audit log
# ---------------------------------------------------------------------------
resource "azurerm_storage_table" "violations" {
  name                 = "PolicyViolations"
  storage_account_name = azurerm_storage_account.tfstate.name
}
