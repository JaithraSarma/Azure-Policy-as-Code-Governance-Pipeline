"""
Rule 6 — SQL_FIREWALL_OPEN

Checks that SQL server firewall rules do not allow unrestricted public access
or internal Azure services access (0.0.0.0).
Severity: HIGH
"""

from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule


class SqlFirewallOpenRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "SQL_FIREWALL_OPEN"

    @property
    def description(self) -> str:
        return (
            "SQL Server firewall rules must not allow unrestricted access "
            "or broad access to Azure internal services (e.g. 0.0.0.0)."
        )

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        if resource_type not in ("azurerm_sql_firewall_rule", "azurerm_mssql_firewall_rule"):
            return []

        start_ip = resource_values.get("start_ip_address")
        end_ip = resource_values.get("end_ip_address")

        start_ip_str = str(start_ip).strip() if start_ip is not None else ""
        end_ip_str = str(end_ip).strip() if end_ip is not None else ""

        # Intended Policy: We treat any wildcard (*) in either field as unrestricted.
        # We also flag 0.0.0.0 -> 0.0.0.0 (Azure services) and 0.0.0.0 -> 255.255.255.255 (full internet)
        is_unrestricted = False
        if start_ip_str == "*" or end_ip_str == "*":
            is_unrestricted = True
        elif start_ip_str == "0.0.0.0" and end_ip_str in ("0.0.0.0", "255.255.255.255"):
            is_unrestricted = True

        if not is_unrestricted:
            return []

        return [
            Violation(
                rule_id=self.rule_id,
                resource_address=resource_address,
                resource_type=resource_type,
                severity=Severity.HIGH,
                message=(
                    f"SQL Firewall rule allows unrestricted access (IP range: {start_ip_str} to {end_ip_str}). "
                    "Ensure firewall rules only permit known CIDRs or secure private connections."
                ),
                details={
                    "start_ip_address": start_ip,
                    "end_ip_address": end_ip,
                },
            )
        ]
