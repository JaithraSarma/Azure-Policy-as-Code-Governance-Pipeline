"""
Abstract base class for all policy rules.
"""

from abc import ABC, abstractmethod
from typing import Any

from policy_engine.models import Violation


class PolicyRule(ABC):
    """
    Base class that every policy rule must extend.

    Each rule receives the *planned values* for a single resource change
    from the Terraform plan JSON and returns zero or more Violations.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this rule (e.g. 'PUBLIC_STORAGE')."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule checks."""

    @abstractmethod
    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        """
        Evaluate a single resource against this rule.

        Args:
            resource_address: The Terraform address (e.g. azurerm_storage_account.demo).
            resource_type:    The resource type string.
            resource_values:  The `planned_values` dict for the resource.

        Returns:
            A list of Violation objects (empty if compliant).
        """
