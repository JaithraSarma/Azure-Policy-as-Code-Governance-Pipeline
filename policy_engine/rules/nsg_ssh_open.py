"""
Rule 3 — NSG_SSH_OPEN

Detects Network Security Group rules that allow inbound SSH (port 22)
from any source (0.0.0.0/0 or *).
Severity: HIGH
"""

from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule

OPEN_SOURCES = {"0.0.0.0/0", "*", "any", "internet"}
SSH_PORT = "22"


class NsgSshOpenRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "NSG_SSH_OPEN"

    @property
    def description(self) -> str:
        return (
            "NSG rules must not allow inbound SSH (port 22) from "
            "0.0.0.0/0 or *. Restrict source addresses."
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _port_matches_ssh(port_range: str | None) -> bool:
        """Return True if port_range includes port 22."""
        if port_range is None:
            return False
        port_range = str(port_range).strip()
        if port_range in ("*", "22"):
            return True
        if "-" in port_range:
            try:
                low, high = port_range.split("-", 1)
                return int(low) <= 22 <= int(high)
            except ValueError:
                return False
        return False

    @staticmethod
    def _source_is_open(source: str | None) -> bool:
        """Return True if the source prefix is wide open."""
        if source is None:
            return False
        return source.strip().lower() in OPEN_SOURCES

    # ------------------------------------------------------------------
    # Evaluate standalone azurerm_network_security_rule resources
    # ------------------------------------------------------------------
    def _check_standalone_rule(
        self,
        resource_address: str,
        resource_type: str,
        values: dict[str, Any],
    ) -> list[Violation]:
        if resource_type != "azurerm_network_security_rule":
            return []

        direction = (values.get("direction") or "").lower()
        access = (values.get("access") or "").lower()
        protocol = (values.get("protocol") or "").lower()

        if direction != "inbound" or access != "allow":
            return []
        if protocol not in ("tcp", "*"):
            return []

        dst_port = values.get("destination_port_range")
        source = values.get("source_address_prefix")

        # Also check source_address_prefixes (list form)
        source_prefixes = values.get("source_address_prefixes") or []

        sources_open = self._source_is_open(source) or any(
            self._source_is_open(s) for s in source_prefixes
        )

        if self._port_matches_ssh(dst_port) and sources_open:
            return [
                Violation(
                    rule_id=self.rule_id,
                    resource_address=resource_address,
                    resource_type=resource_type,
                    severity=Severity.HIGH,
                    message=(
                        "NSG rule allows inbound SSH (port 22) from the public "
                        "internet. Restrict source_address_prefix to a known CIDR."
                    ),
                    details={
                        "direction": direction,
                        "destination_port_range": dst_port,
                        "source_address_prefix": source,
                    },
                )
            ]
        return []

    # ------------------------------------------------------------------
    # Evaluate inline security_rule blocks inside azurerm_network_security_group
    # ------------------------------------------------------------------
    def _check_inline_rules(
        self,
        resource_address: str,
        resource_type: str,
        values: dict[str, Any],
    ) -> list[Violation]:
        if resource_type != "azurerm_network_security_group":
            return []

        violations: list[Violation] = []
        security_rules = values.get("security_rule") or []

        for rule in security_rules:
            if not isinstance(rule, dict):
                continue
            direction = (rule.get("direction") or "").lower()
            access = (rule.get("access") or "").lower()
            protocol = (rule.get("protocol") or "").lower()

            if direction != "inbound" or access != "allow":
                continue
            if protocol not in ("tcp", "*"):
                continue

            dst_port = rule.get("destination_port_range")
            source = rule.get("source_address_prefix")
            source_prefixes = rule.get("source_address_prefixes") or []

            sources_open = self._source_is_open(source) or any(
                self._source_is_open(s) for s in source_prefixes
            )

            if self._port_matches_ssh(dst_port) and sources_open:
                violations.append(
                    Violation(
                        rule_id=self.rule_id,
                        resource_address=resource_address,
                        resource_type=resource_type,
                        severity=Severity.HIGH,
                        message=(
                            f"Inline NSG rule '{rule.get('name', 'unknown')}' allows "
                            f"inbound SSH (port 22) from the public internet."
                        ),
                        details={
                            "rule_name": rule.get("name"),
                            "destination_port_range": dst_port,
                            "source_address_prefix": source,
                        },
                    )
                )
        return violations

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------
    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        violations = self._check_standalone_rule(
            resource_address, resource_type, resource_values
        )
        violations += self._check_inline_rules(
            resource_address, resource_type, resource_values
        )
        return violations
