output "storage_account_id" {
  description = "ID of the demo storage account."
  value       = azurerm_storage_account.demo.id
}

output "nsg_id" {
  description = "ID of the demo NSG."
  value       = azurerm_network_security_group.demo.id
}

output "managed_disk_id" {
  description = "ID of the demo managed disk."
  value       = azurerm_managed_disk.demo.id
}
