variable "location" {
  description = "Azure region for demo resources."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group name for demo resources."
  type        = string
  default     = "rg-policy-gate-demo"
}
