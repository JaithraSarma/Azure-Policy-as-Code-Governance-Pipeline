##############################################################################
# Remote state — points to the backend Storage Account provisioned by
# terraform/backend/
##############################################################################

terraform {
  backend "azurerm" {
    resource_group_name  = "rg-policy-gate-backend"
    storage_account_name = "stpolicygatejaith01"
    container_name       = "tfstate"
    key                  = "demo.terraform.tfstate"
  }
}
