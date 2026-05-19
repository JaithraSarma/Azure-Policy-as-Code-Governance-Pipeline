"""
Policy Engine — Orchestrator

Loads a Terraform plan JSON file, iterates over every planned resource
change, runs each registered policy rule, and returns an aggregated
PolicyResult.
"""

import json
from pathlib import Path
from typing import Any

from policy_engine.models import PolicyResult, Violation
from policy_engine.rules import ALL_RULES, PolicyRule


def _extract_resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Walk the plan JSON and extract a flat list of resource dicts,
    each containing 'address', 'type', and 'values'.

    Supports both:
      - planned_values.root_module.resources
      - planned_values.root_module.child_modules[*].resources
      - resource_changes[*] (for action-aware filtering)
    """
    resources: list[dict[str, Any]] = []

    # --- Strategy 1: planned_values ---
    planned = plan.get("planned_values", {})
    root = planned.get("root_module", {})

    for res in root.get("resources", []):
        resources.append(
            {
                "address": res.get("address", "unknown"),
                "type": res.get("type", "unknown"),
                "values": res.get("values", {}),
            }
        )

    # Child modules (nested)
    for module in root.get("child_modules", []):
        for res in module.get("resources", []):
            resources.append(
                {
                    "address": res.get("address", "unknown"),
                    "type": res.get("type", "unknown"),
                    "values": res.get("values", {}),
                }
            )

    # --- Strategy 2: resource_changes (fallback / supplement) ---
    if not resources:
        for change in plan.get("resource_changes", []):
            actions = change.get("change", {}).get("actions", [])
            # Only evaluate resources being created or updated
            if "create" in actions or "update" in actions:
                after = change.get("change", {}).get("after", {})
                resources.append(
                    {
                        "address": change.get("address", "unknown"),
                        "type": change.get("type", "unknown"),
                        "values": after,
                    }
                )

    return resources


def evaluate_plan(
    plan_path: str | Path,
    rules: list[PolicyRule] | None = None,
) -> PolicyResult:
    """
    Evaluate a Terraform plan JSON file against all policy rules.

    Args:
        plan_path: Path to the tfplan.json file.
        rules:     Optional list of rules to run (defaults to ALL_RULES).

    Returns:
        A PolicyResult with all violations and scan metadata.
    """
    plan_path = Path(plan_path)
    with plan_path.open("r", encoding="utf-8") as f:
        plan = json.load(f)

    if rules is None:
        rules = ALL_RULES

    resources = _extract_resources(plan)
    all_violations: list[Violation] = []

    for resource in resources:
        address = resource["address"]
        rtype = resource["type"]
        values = resource["values"]

        for rule in rules:
            violations = rule.evaluate(address, rtype, values)
            all_violations.extend(violations)

    result = PolicyResult(
        violations=all_violations,
        resources_scanned=len(resources),
    )
    return result


def evaluate_plan_dict(
    plan: dict[str, Any],
    rules: list[PolicyRule] | None = None,
) -> PolicyResult:
    """
    Same as evaluate_plan but accepts an already-parsed dict.
    Useful for testing.
    """
    if rules is None:
        rules = ALL_RULES

    resources = _extract_resources(plan)
    all_violations: list[Violation] = []

    for resource in resources:
        address = resource["address"]
        rtype = resource["type"]
        values = resource["values"]

        for rule in rules:
            violations = rule.evaluate(address, rtype, values)
            all_violations.extend(violations)

    return PolicyResult(
        violations=all_violations,
        resources_scanned=len(resources),
    )
