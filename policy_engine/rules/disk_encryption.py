"""
Rule 5 — DISK_ENCRYPTION

Checks that managed disks have encryption configured — either via
a disk_encryption_set_id or encryption_settings block.
Severity: HIGH
"""

from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule


class DiskEncryptionRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "DISK_ENCRYPTION"

    @property
    def description(self) -> str:
        return (
            "Managed disks must have encryption enabled via "
            "disk_encryption_set_id or encryption_settings."
        )

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        if resource_type != "azurerm_managed_disk":
            return []

        has_des = bool(resource_values.get("disk_encryption_set_id"))
        encryption_settings = resource_values.get("encryption_settings") or []

        # encryption_settings can be a list of dicts or a single dict
        has_enc_settings = False
        if isinstance(encryption_settings, list) and len(encryption_settings) > 0:
            for es in encryption_settings:
                if isinstance(es, dict) and es.get("enabled", False):
                    has_enc_settings = True
                    break
        elif isinstance(encryption_settings, dict):
            has_enc_settings = encryption_settings.get("enabled", False)

        if has_des or has_enc_settings:
            return []

        return [
            Violation(
                rule_id=self.rule_id,
                resource_address=resource_address,
                resource_type=resource_type,
                severity=Severity.HIGH,
                message=(
                    "Managed disk does not have encryption configured. "
                    "Set disk_encryption_set_id or enable encryption_settings."
                ),
                details={
                    "disk_encryption_set_id": None,
                    "encryption_settings": None,
                },
            )
        ]
