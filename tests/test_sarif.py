"""
Unit tests for the SARIF format exporter.
"""

import json
import sys
from pathlib import Path

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from policy_engine.models import Severity, Violation, PolicyResult
from policy_engine.sarif import format_sarif


def test_format_sarif_schema():
    """Verify that the generated SARIF format complies with the schema structure."""
    violations = [
        Violation(
            rule_id="PUBLIC_STORAGE",
            resource_address="azurerm_storage_account.bad",
            resource_type="azurerm_storage_account",
            severity=Severity.HIGH,
            message="Public access is enabled.",
            details={"public": True}
        )
    ]
    result = PolicyResult(violations=violations, resources_scanned=1)

    sarif_str = format_sarif(result)
    doc = json.loads(sarif_str)

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert "runs" in doc
    assert len(doc["runs"]) == 1

    run = doc["runs"][0]
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "Azure Policy Gate"

    # Verify rules are present in tool metadata
    driver_rules = run["tool"]["driver"]["rules"]
    assert len(driver_rules) > 0
    rule_ids = {r["id"] for r in driver_rules}
    assert "PUBLIC_STORAGE" in rule_ids
    assert "SQL_FIREWALL_OPEN" in rule_ids

    # Verify results are present and mapped
    results = run["results"]
    assert len(results) == 1
    res = results[0]
    assert res["ruleId"] == "PUBLIC_STORAGE"
    assert res["level"] == "error"
    assert res["message"]["text"] == "Public access is enabled."
    assert res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "azurerm_storage_account.bad"


def test_format_sarif_severity_mapping():
    """Verify that rule severities correctly map to SARIF levels (error, warning, note)."""
    violations = [
        Violation(
            rule_id="PUBLIC_STORAGE",
            resource_address="azurerm_storage_account.bad",
            resource_type="azurerm_storage_account",
            severity=Severity.HIGH,
            message="HIGH severity",
        ),
        Violation(
            rule_id="NAMING_CONVENTION",
            resource_address="azurerm_resource_group.bad",
            resource_type="azurerm_resource_group",
            severity=Severity.MEDIUM,
            message="MEDIUM severity",
        ),
        Violation(
            rule_id="REQUIRED_TAGS",
            resource_address="azurerm_virtual_network.bad",
            resource_type="azurerm_virtual_network",
            severity=Severity.LOW,
            message="LOW severity",
        )
    ]
    result = PolicyResult(violations=violations, resources_scanned=3)

    sarif_str = format_sarif(result)
    doc = json.loads(sarif_str)
    results = doc["runs"][0]["results"]

    assert results[0]["level"] == "error"
    assert results[1]["level"] == "warning"
    assert results[2]["level"] == "note"


def test_format_sarif_with_exemptions():
    """Verify that exempted violations include suppression metadata in the SARIF result."""
    violations = [
        Violation(
            rule_id="PUBLIC_STORAGE",
            resource_address="azurerm_storage_account.bad",
            resource_type="azurerm_storage_account",
            severity=Severity.HIGH,
            message="Public storage is allowed.",
            exempted=True,
            exemption_reason="Dev sandbox testing approval"
        )
    ]
    result = PolicyResult(violations=violations, resources_scanned=1)

    sarif_str = format_sarif(result)
    doc = json.loads(sarif_str)
    results = doc["runs"][0]["results"]

    assert len(results) == 1
    res = results[0]
    assert "suppressions" in res
    assert len(res["suppressions"]) == 1
    supp = res["suppressions"][0]
    assert supp["kind"] == "external"
    assert supp["justification"] == "Dev sandbox testing approval"
