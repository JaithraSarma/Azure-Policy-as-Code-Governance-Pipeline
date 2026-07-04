"""
Unit tests for the policy engine exemptions loading and validation.
"""

import sys
from pathlib import Path
import pytest

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from policy_engine.models import Severity
from policy_engine.engine import evaluate_plan_dict
from policy_engine.exemptions import (
    load_exemptions,
    validate_and_normalize_exemptions,
    ExemptionConfigError,
)


def make_plan_with_resources(resources_list: list[tuple[str, str, dict]]) -> dict:
    """Helper to construct a planned_values plan dict with multiple resources."""
    resources_data = []
    for address, rtype, values in resources_list:
        resources_data.append({"address": address, "type": rtype, "values": values})

    return {
        "planned_values": {
            "root_module": {
                "resources": resources_data
            }
        }
    }


def test_missing_exemptions_fallback():
    """Verify that if exemptions are absent, no violations are exempted."""
    plan = make_plan_with_resources([
        ("azurerm_storage_account.test", "azurerm_storage_account", {"public_network_access_enabled": True})
    ])
    result = evaluate_plan_dict(plan, exemptions=None)
    assert len(result.violations) >= 1
    assert all(not v.exempted for v in result.violations)
    assert result.has_high_severity is True


def test_valid_exemption_bypasses_failure():
    """Verify that an exempted violation excludes itself from has_high_severity."""
    exemptions = {
        "azurerm_storage_account.test": {
            "PUBLIC_STORAGE": {
                "reason": "Temporary dev sandbox testing"
            }
        }
    }
    plan = make_plan_with_resources([
        ("azurerm_storage_account.test", "azurerm_storage_account", {
            "name": "sttest",
            "public_network_access_enabled": True,
            "tags": {
                "owner": "team1",
                "env": "dev",
                "project": "project1",
                "cost-centre": "cc1"
            }
        })
    ])

    result = evaluate_plan_dict(plan, exemptions=exemptions)
    assert len(result.violations) == 1
    v = result.violations[0]
    assert v.exempted is True
    assert v.exemption_reason == "Temporary dev sandbox testing"
    # Even though it's a HIGH violation, it's exempted, so has_high_severity must be False
    assert result.has_high_severity is False


def test_bare_suppression_raises_error():
    """Verify that exemptions with missing/empty reasons raise ExemptionConfigError."""
    # Case 1: Empty string reason directly
    config_empty_str = {
        "exemptions": {
            "azurerm_storage_account.test": {
                "PUBLIC_STORAGE": ""
            }
        }
    }
    with pytest.raises(ExemptionConfigError) as exc_info:
        validate_and_normalize_exemptions(config_empty_str)
    assert "bare suppressions not allowed" in str(exc_info.value)

    # Case 2: Dict structure missing 'reason' key
    config_missing_reason_key = {
        "exemptions": {
            "azurerm_storage_account.test": {
                "PUBLIC_STORAGE": {"ticket": "JIRA-123"}
            }
        }
    }
    with pytest.raises(ExemptionConfigError) as exc_info:
        validate_and_normalize_exemptions(config_missing_reason_key)
    assert "missing a 'reason' key" in str(exc_info.value)

    # Case 3: Dict structure with empty reason value
    config_empty_reason_val = {
        "exemptions": {
            "azurerm_storage_account.test": {
                "PUBLIC_STORAGE": {"reason": "   "}
            }
        }
    }
    with pytest.raises(ExemptionConfigError) as exc_info:
        validate_and_normalize_exemptions(config_empty_reason_val)
    assert "must be a non-empty string" in str(exc_info.value)


def test_unknown_rule_id_raises_error():
    """Verify that an exemption using an unknown rule ID raises an error."""
    config = {
        "exemptions": {
            "azurerm_storage_account.test": {
                "INVALID_RULE_NAME": "reason"
            }
        }
    }
    with pytest.raises(ExemptionConfigError) as exc_info:
        validate_and_normalize_exemptions(config)
    assert "Unknown rule ID" in str(exc_info.value)


def test_unknown_resource_raises_error():
    """Verify that an exemption for a resource not present in the plan raises an error."""
    exemptions = {
        "azurerm_storage_account.non_existent": {
            "PUBLIC_STORAGE": {
                "reason": "Not in the plan"
            }
        }
    }
    plan = make_plan_with_resources([
        ("azurerm_resource_group.test", "azurerm_resource_group", {"name": "rg-test"})
    ])

    with pytest.raises(ExemptionConfigError) as exc_info:
        evaluate_plan_dict(plan, exemptions=exemptions)
    assert "does not exist in the plan" in str(exc_info.value)


def test_targeted_exemption_rule_specific():
    """Verify that an exemption for rule X doesn't suppress violations for rule Y."""
    exemptions = {
        "azurerm_storage_account.test": {
            "PUBLIC_STORAGE": {
                "reason": "Allow public storage temporarily"
            }
        }
    }
    # Storage account is public (PUBLIC_STORAGE) AND has no tags (REQUIRED_TAGS)
    plan = make_plan_with_resources([
        ("azurerm_storage_account.test", "azurerm_storage_account", {
            "public_network_access_enabled": True,
            "tags": {}
        })
    ])

    result = evaluate_plan_dict(plan, exemptions=exemptions)
    violations = result.violations
    assert len(violations) >= 2

    public_storage_v = [v for v in violations if v.rule_id == "PUBLIC_STORAGE"][0]
    required_tags_v = [v for v in violations if v.rule_id == "REQUIRED_TAGS"][0]

    assert public_storage_v.exempted is True
    assert required_tags_v.exempted is False
    # The REQUIRED_TAGS violation is HIGH and not exempted, so pipeline should still fail
    assert result.has_high_severity is True


def test_invalid_yaml_raises_error(tmp_path):
    """Verify that malformed YAML raises ExemptionConfigError."""
    bad_yaml_file = tmp_path / "exemptions_bad.yml"
    bad_yaml_file.write_text("exemptions:\n  azurerm_storage_account.test:\n    PUBLIC_STORAGE: : :", encoding="utf-8")

    with pytest.raises(ExemptionConfigError) as exc_info:
        load_exemptions(bad_yaml_file)
    assert "Malformed YAML" in str(exc_info.value)


def test_invalid_exemptions_schema():
    """Verify that validation flags wrong types for exemptions blocks."""
    # Top-level exemptions is not a dict
    with pytest.raises(ExemptionConfigError):
        validate_and_normalize_exemptions({"exemptions": "not a dict"})

    # Resource config is not a dict
    with pytest.raises(ExemptionConfigError):
        validate_and_normalize_exemptions({"exemptions": {"azurerm_storage_account.test": "not a dict"}})

    # Rule configuration maps to unsupported type
    with pytest.raises(ExemptionConfigError):
        validate_and_normalize_exemptions({"exemptions": {"azurerm_storage_account.test": {"PUBLIC_STORAGE": 123}}})
