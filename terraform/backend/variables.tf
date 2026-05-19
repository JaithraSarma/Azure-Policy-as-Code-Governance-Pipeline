variable "location" {
  description = "Azure region for all backend resources."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Name of the resource group for policy-gate backend."
  type        = string
  default     = "rg-policy-gate-backend"
}

variable "storage_account_name" {
  description = "Globally unique name for the Storage Account (3-24 lowercase alphanumeric)."
  type        = string
  default     = "stpolicygate<unique>"

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Storage account name must be 3-24 lowercase alphanumeric characters."
  }
}

variable "owner" {
  description = "Owner tag value."
  type        = string
  default     = "platform-engineering"
}

variable "cost_centre" {
  description = "Cost centre tag value."
  type        = string
  default     = "CC-001"
}
