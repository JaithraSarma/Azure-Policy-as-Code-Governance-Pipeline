output "resource_group_name" {
  description = "Name of the backend resource group."
  value       = azurerm_resource_group.policy_gate.name
}

output "storage_account_name" {
  description = "Name of the Storage Account used for state and violation logs."
  value       = azurerm_storage_account.tfstate.name
}

output "storage_account_primary_access_key" {
  description = "Primary access key for the Storage Account."
  value       = azurerm_storage_account.tfstate.primary_access_key
  sensitive   = true
}

output "tfstate_container_name" {
  description = "Name of the blob container for Terraform remote state."
  value       = azurerm_storage_container.tfstate.name
}

output "violations_table_name" {
  description = "Name of the Table Storage table for violation records."
  value       = azurerm_storage_table.violations.name
}

output "table_endpoint" {
  description = "Table Storage endpoint URL."
  value       = azurerm_storage_account.tfstate.primary_table_endpoint
}
