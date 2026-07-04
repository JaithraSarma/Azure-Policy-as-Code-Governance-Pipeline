"""
Unit tests for the policy engine configuration loading and schema validation.
"""

import sys
from pathlib import Path
import pytest

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from policy_engine.models import Severity
from policy_engine.engine import evaluate_plan_dict
from policy_engine.config import load_policy_config, validate_policy_config, PolicyConfigError


def make_plan_with_resource(address: str, rtype: str, values: dict) -> dict:
    """Helper to construct a minimal planned_values plan dict with one resource."""
    return {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": address, "type": rtype, "values": values}
                ]
            }
        }
    }


def test_missing_config_fallback():
    """Verify that if config is absent or empty, the default rules and severities are used."""
    plan = make_plan_with_resource(
        "azurerm_storage_account.test",
        "azurerm_storage_account",
        {"tags": {}}
    )
    # With no config, REQUIRED_TAGS should trigger with default HIGH severity
    result = evaluate_plan_dict(plan, config=None)
    tags_violations = [v for v in result.violations if v.rule_id == "REQUIRED_TAGS"]
    assert len(tags_violations) == 1
    assert tags_violations[0].severity == Severity.HIGH


def test_config_disables_rule():
    """Verify that a rule can be disabled in the configuration."""
    config = {
        "rules": {
            "REQUIRED_TAGS": {
                "enabled": False
            }
        }
    }
    plan = make_plan_with_resource(
        "azurerm_storage_account.test",
        "azurerm_storage_account",
        {"tags": {}}
    )
    # REQUIRED_TAGS is disabled, so we should get no violations for it
    result = evaluate_plan_dict(plan, config=config)
    tags_violations = [v for v in result.violations if v.rule_id == "REQUIRED_TAGS"]
    assert len(tags_violations) == 0


def test_config_overrides_severity():
    """Verify that rule severity can be overridden."""
    config = {
        "rules": {
            "REQUIRED_TAGS": {
                "severity": "LOW"
            }
        }
    }
    plan = make_plan_with_resource(
        "azurerm_storage_account.test",
        "azurerm_storage_account",
        {"tags": {}}
    )
    result = evaluate_plan_dict(plan, config=config)
    tags_violations = [v for v in result.violations if v.rule_id == "REQUIRED_TAGS"]
    assert len(tags_violations) == 1
    assert tags_violations[0].severity == Severity.LOW


def test_config_overrides_parameters_tags():
    """Verify that REQUIRED_TAGS rule parameters can be overridden."""
    config = {
        "rules": {
            "REQUIRED_TAGS": {
                "parameters": {
                    "tags": ["owner", "custom-tag"]
                }
            }
        }
    }

    # Case 1: Resource is missing the custom-tag
    plan_bad = make_plan_with_resource(
        "azurerm_storage_account.test",
        "azurerm_storage_account",
        {"tags": {"owner": "team1"}}
    )
    result_bad = evaluate_plan_dict(plan_bad, config=config)
    tags_violations_bad = [v for v in result_bad.violations if v.rule_id == "REQUIRED_TAGS"]
    assert len(tags_violations_bad) == 1
    assert "custom-tag" in tags_violations_bad[0].message

    # Case 2: Resource has both tags
    plan_good = make_plan_with_resource(
        "azurerm_storage_account.test",
        "azurerm_storage_account",
        {"tags": {"owner": "team1", "custom-tag": "val"}}
    )
    result_good = evaluate_plan_dict(plan_good, config=config)
    tags_violations_good = [v for v in result_good.violations if v.rule_id == "REQUIRED_TAGS"]
    assert len(tags_violations_good) == 0


def test_config_overrides_parameters_prefixes():
    """Verify that NAMING_CONVENTION rule prefixes can be overridden."""
    config = {
        "rules": {
            "NAMING_CONVENTION": {
                "parameters": {
                    "prefixes": {
                        "azurerm_resource_group": "rgx-",
                        "azurerm_storage_account": "stx"
                    }
                }
            }
        }
    }

    # Case 1: RG matches new prefix, storage account name is valid
    plan_good = make_plan_with_resource(
        "azurerm_resource_group.test",
        "azurerm_resource_group",
        {"name": "rgx-myrg"}
    )
    result_good = evaluate_plan_dict(plan_good, config=config)
    naming_violations_good = [v for v in result_good.violations if v.rule_id == "NAMING_CONVENTION"]
    assert len(naming_violations_good) == 0

    # Case 2: RG matches default 'rg-' prefix but not overridden 'rgx-' prefix
    plan_bad = make_plan_with_resource(
        "azurerm_resource_group.test",
        "azurerm_resource_group",
        {"name": "rg-myrg"}
    )
    result_bad = evaluate_plan_dict(plan_bad, config=config)
    naming_violations_bad = [v for v in result_bad.violations if v.rule_id == "NAMING_CONVENTION"]
    assert len(naming_violations_bad) == 1


def test_invalid_yaml_raises_error(tmp_path):
    """Verify that loading invalid YAML raises a PolicyConfigError."""
    bad_yaml_file = tmp_path / "policy_bad.yml"
    bad_yaml_file.write_text("rules:\n  REQUIRED_TAGS:\n    enabled: : :", encoding="utf-8")

    with pytest.raises(PolicyConfigError) as exc_info:
        load_policy_config(bad_yaml_file)
    assert "Malformed YAML" in str(exc_info.value)


def test_strict_parameter_validation():
    """Verify that unknown configuration parameters fail validation loudly."""
    # Invalid root type
    with pytest.raises(PolicyConfigError):
        validate_policy_config("invalid root structure")

    # Invalid rules type
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": "invalid rules structure"})

    # Invalid rule config type
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"REQUIRED_TAGS": "not a dict"}})

    # Invalid enabled key type
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"REQUIRED_TAGS": {"enabled": "yes"}}})

    # Invalid severity key value
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"REQUIRED_TAGS": {"severity": "CRITICAL"}}})

    # Invalid parameters type
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"REQUIRED_TAGS": {"parameters": "not a dict"}}})

    # Unsupported parameter key for REQUIRED_TAGS
    with pytest.raises(PolicyConfigError) as exc_info:
        validate_policy_config({"rules": {"REQUIRED_TAGS": {"parameters": {"unsupported_param": 1}}}})
    assert "only supports parameter 'tags'" in str(exc_info.value)

    # Invalid parameter tags list type
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"REQUIRED_TAGS": {"parameters": {"tags": "not a list"}}}})

    # Invalid tag elements
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"REQUIRED_TAGS": {"parameters": {"tags": [123]}}}})

    # Unsupported parameter key for NAMING_CONVENTION
    with pytest.raises(PolicyConfigError) as exc_info:
        validate_policy_config({"rules": {"NAMING_CONVENTION": {"parameters": {"unsupported_param": 1}}}})
    assert "only supports parameter 'prefixes'" in str(exc_info.value)

    # Invalid parameter prefixes dict type
    with pytest.raises(PolicyConfigError):
        validate_policy_config({"rules": {"NAMING_CONVENTION": {"parameters": {"prefixes": "not a dict"}}}})

    # Rule without supported parameters (e.g. PUBLIC_STORAGE) receiving parameters
    with pytest.raises(PolicyConfigError) as exc_info:
        validate_policy_config({"rules": {"PUBLIC_STORAGE": {"parameters": {"tags": []}}}})
    assert "does not support any parameters" in str(exc_info.value)
