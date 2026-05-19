"""
Rule 2 — REQUIRED_TAGS

Every Azure resource that supports tags must have the following tags:
  - owner
  - env
  - project
  - cost-centre

Severity: HIGH
"""

from typing import Any

from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule

REQUIRED_TAGS = {"owner", "env", "project", "cost-centre"}

# Resource types that typically support tags in azurerm
TAGGABLE_PREFIXES = ("azurerm_",)


class RequiredTagsRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "REQUIRED_TAGS"

    @property
    def description(self) -> str:
        return (
            "All Azure resources must include the following tags: "
            + ", ".join(sorted(REQUIRED_TAGS))
            + "."
        )

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        # Only check azurerm resources (they support tags)
        if not any(resource_type.startswith(p) for p in TAGGABLE_PREFIXES):
            return []

        # Some resource types don't have a tags attribute — skip them
        # If "tags" key is absent entirely, treat as no tags
        tags = resource_values.get("tags") or {}

        # Normalise tag keys to lowercase for comparison
        existing_keys = {k.lower() for k in tags}
        missing = REQUIRED_TAGS - existing_keys

        if not missing:
            return []

        return [
            Violation(
                rule_id=self.rule_id,
                resource_address=resource_address,
                resource_type=resource_type,
                severity=Severity.HIGH,
                message=(
                    f"Resource is missing required tag(s): {', '.join(sorted(missing))}. "
                    f"All resources must have: {', '.join(sorted(REQUIRED_TAGS))}."
                ),
                details={"missing_tags": sorted(missing)},
            )
        ]
