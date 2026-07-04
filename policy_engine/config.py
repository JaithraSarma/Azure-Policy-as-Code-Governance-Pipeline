"""
Configuration module for loading and validating policy.yml.
"""

from pathlib import Path
from typing import Any
import yaml


class PolicyConfigError(Exception):
    """Raised when there is an error loading or validating the policy configuration."""
    pass


def load_policy_config(config_path: Path | str | None = "policy.yml") -> dict[str, Any] | None:
    """
    Load a policy configuration file and validate it.

    Args:
        config_path: Path to the configuration file (default is 'policy.yml').

    Returns:
        The validated configuration dictionary or None if config_path is None or file is absent.
    """
    if config_path is None:
        return None

    path = Path(config_path)
    if not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as exc:
        raise PolicyConfigError(f"Malformed YAML in config file: {exc}") from exc

    if config is None:
        return None

    validate_policy_config(config)
    return config


def validate_policy_config(config: Any) -> None:
    """
    Validate the schema and parameters in the configuration dictionary.
    Raises PolicyConfigError if validation fails.
    """
    if not isinstance(config, dict):
        raise PolicyConfigError("Configuration must be a key-value mapping (dictionary).")

    if "rules" not in config:
        return

    rules = config["rules"]
    if not isinstance(rules, dict):
        raise PolicyConfigError("The 'rules' key must map to a dictionary of rules configuration.")

    for rule_id, rule_conf in rules.items():
        if not isinstance(rule_conf, dict):
            raise PolicyConfigError(f"Configuration for rule '{rule_id}' must be a dictionary.")

        # Validate 'enabled'
        if "enabled" in rule_conf:
            if not isinstance(rule_conf["enabled"], bool):
                raise PolicyConfigError(f"Rule '{rule_id}' 'enabled' key must be a boolean.")

        # Validate 'severity'
        if "severity" in rule_conf:
            severity = rule_conf["severity"]
            if severity not in ("HIGH", "MEDIUM", "LOW"):
                raise PolicyConfigError(
                    f"Rule '{rule_id}' 'severity' must be one of 'HIGH', 'MEDIUM', 'LOW'. "
                    f"Got: '{severity}'"
                )

        # Validate 'parameters' strictly
        if "parameters" in rule_conf:
            params = rule_conf["parameters"]
            if not isinstance(params, dict):
                raise PolicyConfigError(f"Rule '{rule_id}' 'parameters' key must be a dictionary.")

            # Validate parameter keys strictly based on rule ID
            if rule_id == "REQUIRED_TAGS":
                for param_key in params:
                    if param_key != "tags":
                        raise PolicyConfigError(
                            f"Rule 'REQUIRED_TAGS' only supports parameter 'tags'. Got: '{param_key}'"
                        )
                if "tags" in params:
                    tags = params["tags"]
                    if not isinstance(tags, list):
                        raise PolicyConfigError("Rule 'REQUIRED_TAGS' parameter 'tags' must be a list of strings.")
                    for t in tags:
                        if not isinstance(t, str):
                            raise PolicyConfigError("Rule 'REQUIRED_TAGS' tags list elements must be strings.")
            elif rule_id == "NAMING_CONVENTION":
                for param_key in params:
                    if param_key != "prefixes":
                        raise PolicyConfigError(
                            f"Rule 'NAMING_CONVENTION' only supports parameter 'prefixes'. Got: '{param_key}'"
                        )
                if "prefixes" in params:
                    prefixes = params["prefixes"]
                    if not isinstance(prefixes, dict):
                        raise PolicyConfigError("Rule 'NAMING_CONVENTION' parameter 'prefixes' must be a dictionary.")
                    for rtype, prefix in prefixes.items():
                        if not isinstance(rtype, str) or not isinstance(prefix, str):
                            raise PolicyConfigError(
                                "Rule 'NAMING_CONVENTION' prefixes mapping keys and values must be strings."
                            )
            else:
                # Other rules do not support parameters currently
                if params:
                    raise PolicyConfigError(
                        f"Rule '{rule_id}' does not support any parameters. Got: {list(params.keys())}"
                    )


def apply_config_to_rules(rules: list[Any], config: dict[str, Any] | None) -> list[Any]:
    """
    Filter rules list for enabled rules and apply configuration parameter overrides.
    """
    if not config or "rules" not in config:
        return rules

    rule_configs = config["rules"]
    enabled_rules = []

    for rule in rules:
        rule_id = rule.rule_id
        rule_conf = rule_configs.get(rule_id, {})

        # Check if explicitly disabled
        if not rule_conf.get("enabled", True):
            continue

        # Apply parameters strictly
        params = rule_conf.get("parameters", {})
        if params:
            if rule_id == "REQUIRED_TAGS" and "tags" in params:
                rule.required_tags = set(params["tags"])
            elif rule_id == "NAMING_CONVENTION" and "prefixes" in params:
                import re
                from policy_engine.rules.naming_convention import NAMING_PATTERNS
                custom_patterns = dict(NAMING_PATTERNS)
                for rtype, prefix in params["prefixes"].items():
                    if rtype == "azurerm_storage_account":
                        pattern = re.compile(rf"^{prefix}[a-z0-9]{{{max(0, 3-len(prefix))},{max(0, 24-len(prefix))}}}$")
                        desc = f"{prefix}<workload> (3-24 lowercase alphanumeric, no hyphens)"
                    else:
                        pattern = re.compile(rf"^{prefix}[a-z0-9\-]+$")
                        desc = f"{prefix}<workload> (lowercase, hyphens allowed)"
                    custom_patterns[rtype] = (pattern, desc)
                rule.naming_patterns = custom_patterns

        enabled_rules.append(rule)

    return enabled_rules
