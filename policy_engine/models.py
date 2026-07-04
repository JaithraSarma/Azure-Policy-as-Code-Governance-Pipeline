"""
Data models for the policy engine.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    """Severity levels for policy violations."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Violation:
    """Represents a single policy violation found during evaluation."""

    rule_id: str
    resource_address: str
    resource_type: str
    severity: Severity
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    exempted: bool = False
    exemption_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a flat dictionary (suitable for Table Storage)."""
        return {
            "rule_id": self.rule_id,
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "severity": self.severity.value,
            "message": self.message,
            "details": str(self.details),
            "exempted": self.exempted,
            "exemption_reason": self.exemption_reason or "",
        }


@dataclass
class PolicyResult:
    """Aggregated result of running all policy rules against a plan."""

    violations: list[Violation] = field(default_factory=list)
    resources_scanned: int = 0

    @property
    def has_high_severity(self) -> bool:
        """Return True if any HIGH severity violations exist."""
        return any(v.severity == Severity.HIGH and not v.exempted for v in self.violations)

    @property
    def summary(self) -> str:
        """Human-readable summary string."""
        high = sum(1 for v in self.violations if v.severity == Severity.HIGH)
        medium = sum(1 for v in self.violations if v.severity == Severity.MEDIUM)
        low = sum(1 for v in self.violations if v.severity == Severity.LOW)
        return (
            f"Scanned {self.resources_scanned} resources — "
            f"{len(self.violations)} violation(s) found "
            f"(HIGH: {high}, MEDIUM: {medium}, LOW: {low})"
        )
