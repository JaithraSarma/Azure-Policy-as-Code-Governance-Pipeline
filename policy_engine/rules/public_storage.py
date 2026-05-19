"""
Rule 1 — PUBLIC_STORAGE

Detects Azure Storage Accounts that have public network access enabled
or overly permissive network rules (default_action = Allow).
Severity: HIGH
"""

from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule


class PublicStorageRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "PUBLIC_STORAGE"

    @property
    def description(self) -> str:
        return (
            "Storage accounts must not be publicly accessible. "
            "public_network_access_enabled must be false and "
            "network_rules.default_action must be 'Deny'."
        )

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        if resource_type != "azurerm_storage_account":
            return []

        violations: list[Violation] = []

        # Check 1: public_network_access_enabled
        public_access = resource_values.get("public_network_access_enabled", False)
        if public_access is True:
            violations.append(
                Violation(
                    rule_id=self.rule_id,
                    resource_address=resource_address,
                    resource_type=resource_type,
                    severity=Severity.HIGH,
                    message=(
                        "Storage account has public_network_access_enabled = true. "
                        "Disable public access to prevent data exposure."
                    ),
                    details={"public_network_access_enabled": True},
                )
            )

        # Check 2: allow_nested_items_to_be_public
        nested_public = resource_values.get("allow_nested_items_to_be_public", False)
        if nested_public is True:
            violations.append(
                Violation(
                    rule_id=self.rule_id,
                    resource_address=resource_address,
                    resource_type=resource_type,
                    severity=Severity.HIGH,
                    message=(
                        "Storage account has allow_nested_items_to_be_public = true. "
                        "Blob-level public access should be disabled."
                    ),
                    details={"allow_nested_items_to_be_public": True},
                )
            )

        # Check 3: network_rules default_action
        network_rules = resource_values.get("network_rules")
        if isinstance(network_rules, list):
            for nr in network_rules:
                if isinstance(nr, dict) and nr.get("default_action", "").lower() == "allow":
                    violations.append(
                        Violation(
                            rule_id=self.rule_id,
                            resource_address=resource_address,
                            resource_type=resource_type,
                            severity=Severity.HIGH,
                            message=(
                                "Storage account network_rules default_action is 'Allow'. "
                                "Set to 'Deny' and whitelist required networks."
                            ),
                            details={"network_rules_default_action": "Allow"},
                        )
                    )
        elif isinstance(network_rules, dict):
            if network_rules.get("default_action", "").lower() == "allow":
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        resource_address=resource_address,
                        resource_type=resource_type,
                        severity=Severity.HIGH,
                        message=(
                            "Storage account network_rules default_action is 'Allow'. "
                            "Set to 'Deny' and whitelist required networks."
                        ),
                        details={"network_rules_default_action": "Allow"},
                    )
                )

        return violations
