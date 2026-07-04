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


from policy_engine.config import load_policy_config, apply_config_to_rules


def evaluate_plan(
    plan_path: str | Path,
    rules: list[PolicyRule] | None = None,
    config_path: str | Path | None = "policy.yml",
) -> PolicyResult:
    """
    Evaluate a Terraform plan JSON file against all policy rules.

    Args:
        plan_path: Path to the tfplan.json file.
        rules:     Optional list of rules to run (defaults to ALL_RULES).
        config_path: Optional path to the configuration YAML file.

    Returns:
        A PolicyResult with all violations and scan metadata.
    """
    plan_path = Path(plan_path)
    with plan_path.open("r", encoding="utf-8") as f:
        plan = json.load(f)

    # Load config exactly once at startup (outermost layer of file reading)
    config = load_policy_config(config_path)

    return evaluate_plan_dict(plan, rules=rules, config=config)


def evaluate_plan_dict(
    plan: dict[str, Any],
    rules: list[PolicyRule] | None = None,
    config: dict[str, Any] | None = None,
) -> PolicyResult:
    """
    Same as evaluate_plan but accepts an already-parsed dict and config object.
    Useful for testing without hitting the filesystem.
    """
    import copy
    from policy_engine.models import Severity

    if rules is None:
        rules = copy.deepcopy(ALL_RULES)
    else:
        # Avoid polluting original rule instances across tests/runs
        rules = copy.deepcopy(rules)

    # Apply enable/disable filtering and parameter overrides before evaluation
    rules = apply_config_to_rules(rules, config)

    resources = _extract_resources(plan)
    all_violations: list[Violation] = []

    for resource in resources:
        address = resource["address"]
        rtype = resource["type"]
        values = resource["values"]

        for rule in rules:
            violations = rule.evaluate(address, rtype, values)

            # Apply severity overrides post-evaluation without modifying rule implementations
            if config and "rules" in config:
                rule_conf = config["rules"].get(rule.rule_id, {})
                severity_str = rule_conf.get("severity")
                if severity_str:
                    severity_override = Severity[severity_str]
                    for v in violations:
                        v.severity = severity_override

            all_violations.extend(violations)

    result = PolicyResult(
        violations=all_violations,
        resources_scanned=len(resources),
    )
    return result
