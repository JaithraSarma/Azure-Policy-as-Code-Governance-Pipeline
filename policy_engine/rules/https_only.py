"""
Rule 7 — HTTPS_ONLY

Checks that App Services, Web Apps, and Function Apps have https_only = true.
Severity: HIGH
"""

from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule

TARGET_TYPES = {
    "azurerm_app_service",
    "azurerm_linux_web_app",
    "azurerm_windows_web_app",
    "azurerm_function_app",
}


class HttpsOnlyRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "HTTPS_ONLY"

    @property
    def description(self) -> str:
        return (
            "App Services, Web Apps, and Function Apps must have HTTPS-only "
            "enabled to prevent insecure HTTP traffic."
        )

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        if resource_type not in TARGET_TYPES:
            return []

        https_only = resource_values.get("https_only", False)

        if https_only is True:
            return []

        return [
            Violation(
                rule_id=self.rule_id,
                resource_address=resource_address,
                resource_type=resource_type,
                severity=Severity.HIGH,
                message=(
                    "Resource does not have HTTPS-only configured. "
                    "Ensure https_only is set to true."
                ),
                details={
                    "https_only": https_only,
                },
            )
        ]
