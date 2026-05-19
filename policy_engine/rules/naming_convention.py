"""
Rule 4 — NAMING_CONVENTION

Validates resource names against per-type regex patterns based on
Microsoft Cloud Adoption Framework naming conventions.
Severity: MEDIUM
"""

import re
from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule

# Map of resource type → (compiled regex, human-readable pattern description)
NAMING_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "azurerm_resource_group": (
        re.compile(r"^rg-[a-z0-9\-]+$"),
        "rg-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_storage_account": (
        re.compile(r"^st[a-z0-9]{3,22}$"),
        "st<workload>  (3-24 lowercase alphanumeric, no hyphens)",
    ),
    "azurerm_virtual_network": (
        re.compile(r"^vnet-[a-z0-9\-]+$"),
        "vnet-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_subnet": (
        re.compile(r"^snet-[a-z0-9\-]+$"),
        "snet-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_network_security_group": (
        re.compile(r"^nsg-[a-z0-9\-]+$"),
        "nsg-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_public_ip": (
        re.compile(r"^pip-[a-z0-9\-]+$"),
        "pip-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_managed_disk": (
        re.compile(r"^disk-[a-z0-9\-]+$"),
        "disk-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_key_vault": (
        re.compile(r"^kv-[a-z0-9\-]+$"),
        "kv-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_linux_virtual_machine": (
        re.compile(r"^vm-[a-z0-9\-]+$"),
        "vm-<workload>  (lowercase, hyphens allowed)",
    ),
    "azurerm_windows_virtual_machine": (
        re.compile(r"^vm-[a-z0-9\-]+$"),
        "vm-<workload>  (lowercase, hyphens allowed)",
    ),
}


class NamingConventionRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "NAMING_CONVENTION"

    @property
    def description(self) -> str:
        return (
            "Resource names must follow Cloud Adoption Framework conventions "
            "(e.g. rg-, st, vnet-, nsg-, disk-, etc.)."
        )

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        pattern_info = NAMING_PATTERNS.get(resource_type)
        if pattern_info is None:
            # No naming rule defined for this type — pass
            return []

        regex, pattern_desc = pattern_info
        name = resource_values.get("name", "")

        if regex.match(name):
            return []

        return [
            Violation(
                rule_id=self.rule_id,
                resource_address=resource_address,
                resource_type=resource_type,
                severity=Severity.MEDIUM,
                message=(
                    f"Resource name '{name}' does not match the required naming "
                    f"convention: {pattern_desc}."
                ),
                details={
                    "actual_name": name,
                    "expected_pattern": pattern_desc,
                },
            )
        ]
