"""
Exemptions module for loading and validating exemptions.yml.
"""

from pathlib import Path
from typing import Any
import yaml

from policy_engine.models import Violation
from policy_engine.rules import ALL_RULES


class ExemptionConfigError(Exception):
    """Raised when there is an error loading or validating the exemptions configuration."""
    pass


def load_exemptions(config_path: Path | str | None = "exemptions.yml") -> dict[str, dict[str, Any]]:
    """
    Load and parse the exemptions file.

    Args:
        config_path: Path to the exemptions YAML file.

    Returns:
        A dictionary mapping resource_address -> rule_id -> { "reason": "reason_str", ... }
    """
    if config_path is None:
        return {}

    path = Path(config_path)
    if not path.is_file():
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as exc:
        raise ExemptionConfigError(f"Malformed YAML in exemptions file: {exc}") from exc

    if config is None:
        return {}

    return validate_and_normalize_exemptions(config)


def validate_and_normalize_exemptions(config: Any) -> dict[str, dict[str, Any]]:
    """
    Validate the exemptions schema and normalize all configurations to a consistent dict format.
    """
    if not isinstance(config, dict):
        raise ExemptionConfigError("Exemptions configuration must be a dictionary.")

    if "exemptions" not in config:
        return {}

    exemptions = config["exemptions"]
    if exemptions is None:
        return {}

    if not isinstance(exemptions, dict):
        raise ExemptionConfigError("The 'exemptions' key must map to a dictionary.")

    known_rule_ids = {rule.rule_id for rule in ALL_RULES}
    normalized: dict[str, dict[str, Any]] = {}

    for resource_address, rules_map in exemptions.items():
        if not isinstance(resource_address, str):
            raise ExemptionConfigError(f"Resource address key must be a string. Got: {resource_address}")

        if not isinstance(rules_map, dict):
            raise ExemptionConfigError(
                f"Exemptions rules block for resource '{resource_address}' must be a dictionary."
            )

        normalized[resource_address] = {}

        for rule_id, raw_val in rules_map.items():
            if not isinstance(rule_id, str):
                raise ExemptionConfigError(f"Rule ID key under '{resource_address}' must be a string.")

            if rule_id not in known_rule_ids:
                raise ExemptionConfigError(
                    f"Unknown rule ID '{rule_id}' specified in exemption for resource '{resource_address}'."
                )

            # Validate reason
            if isinstance(raw_val, str):
                reason = raw_val.strip()
                if not reason:
                    raise ExemptionConfigError(
                        f"Exemption reason for resource '{resource_address}' under rule '{rule_id}' cannot be empty (bare suppressions not allowed)."
                    )
                normalized[resource_address][rule_id] = {"reason": reason}
            elif isinstance(raw_val, dict):
                if "reason" not in raw_val:
                    raise ExemptionConfigError(
                        f"Exemption for resource '{resource_address}' under rule '{rule_id}' is missing a 'reason' key."
                    )
                reason = raw_val["reason"]
                if not isinstance(reason, str) or not reason.strip():
                    raise ExemptionConfigError(
                        f"Exemption reason for resource '{resource_address}' under rule '{rule_id}' must be a non-empty string."
                    )
                # Keep other metadata fields in normalized dictionary for future extensibility
                entry = {k: v for k, v in raw_val.items()}
                entry["reason"] = reason.strip()
                normalized[resource_address][rule_id] = entry
            else:
                raise ExemptionConfigError(
                    f"Invalid exemption value for resource '{resource_address}' under rule '{rule_id}'. Must be a string reason or a dictionary."
                )

    return normalized


def apply_exemptions(
    violations: list[Violation],
    exemptions: dict[str, dict[str, Any]],
    plan_resources: list[str] | None = None,
) -> None:
    """
    Apply exemptions to a list of violations.
    Also validates that all exempted resource addresses exist in plan_resources if provided.
    """
    if not exemptions:
        return

    # Strict resource existence validation
    if plan_resources is not None:
        plan_set = set(plan_resources)
        for exempted_addr in exemptions.keys():
            if exempted_addr not in plan_set:
                raise ExemptionConfigError(
                    f"Exemption defined for resource '{exempted_addr}' which does not exist in the plan."
                )

    for v in violations:
        if v.resource_address in exemptions:
            rules_map = exemptions[v.resource_address]
            if v.rule_id in rules_map:
                v.exempted = True
                v.exemption_reason = rules_map[v.rule_id]["reason"]
