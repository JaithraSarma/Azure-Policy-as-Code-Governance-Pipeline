"""
Unit tests for the Azure Policy Gate policy engine.
"""

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from policy_engine.models import Severity, Violation, PolicyResult
from policy_engine.engine import evaluate_plan, evaluate_plan_dict
from policy_engine.reporter import format_markdown
from policy_engine.rules.public_storage import PublicStorageRule
from policy_engine.rules.required_tags import RequiredTagsRule
from policy_engine.rules.nsg_ssh_open import NsgSshOpenRule
from policy_engine.rules.naming_convention import NamingConventionRule
from policy_engine.rules.disk_encryption import DiskEncryptionRule

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def load_fixture(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


def make_resource(address: str, rtype: str, values: dict) -> dict:
    """Build a minimal planned_values plan dict with one resource."""
    return {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": address, "type": rtype, "values": values}
                ]
            }
        }
    }


# ═══════════════════════════════════════════════════════════════════════════
# Rule 1 — PUBLIC_STORAGE
# ═══════════════════════════════════════════════════════════════════════════

class TestPublicStorageRule:
    rule = PublicStorageRule()

    def test_public_access_enabled(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.bad",
            "azurerm_storage_account",
            {"public_network_access_enabled": True},
        )
        assert len(violations) >= 1
        assert violations[0].severity == Severity.HIGH
        assert violations[0].rule_id == "PUBLIC_STORAGE"

    def test_nested_public_access(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.bad",
            "azurerm_storage_account",
            {"allow_nested_items_to_be_public": True},
        )
        assert any("nested" in v.message.lower() for v in violations)

    def test_network_rules_allow(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.bad",
            "azurerm_storage_account",
            {"network_rules": [{"default_action": "Allow"}]},
        )
        assert any("network_rules" in v.message.lower() for v in violations)

    def test_compliant_storage(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.good",
            "azurerm_storage_account",
            {
                "public_network_access_enabled": False,
                "allow_nested_items_to_be_public": False,
                "network_rules": [{"default_action": "Deny"}],
            },
        )
        assert violations == []

    def test_ignores_non_storage(self):
        violations = self.rule.evaluate(
            "azurerm_resource_group.rg",
            "azurerm_resource_group",
            {"public_network_access_enabled": True},
        )
        assert violations == []


# ═══════════════════════════════════════════════════════════════════════════
# Rule 2 — REQUIRED_TAGS
# ═══════════════════════════════════════════════════════════════════════════

class TestRequiredTagsRule:
    rule = RequiredTagsRule()

    def test_missing_all_tags(self):
        violations = self.rule.evaluate(
            "azurerm_resource_group.bad",
            "azurerm_resource_group",
            {"name": "rg-test"},
        )
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH
        assert "owner" in violations[0].message

    def test_partial_tags(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.partial",
            "azurerm_storage_account",
            {"tags": {"owner": "team", "env": "dev"}},
        )
        assert len(violations) == 1
        details = violations[0].details
        assert "project" in details["missing_tags"]
        assert "cost-centre" in details["missing_tags"]

    def test_all_tags_present(self):
        violations = self.rule.evaluate(
            "azurerm_resource_group.good",
            "azurerm_resource_group",
            {
                "tags": {
                    "owner": "team",
                    "env": "prod",
                    "project": "app",
                    "cost-centre": "CC-100",
                }
            },
        )
        assert violations == []

    def test_ignores_non_azure_types(self):
        violations = self.rule.evaluate(
            "null_resource.test",
            "null_resource",
            {},
        )
        assert violations == []


# ═══════════════════════════════════════════════════════════════════════════
# Rule 3 — NSG_SSH_OPEN
# ═══════════════════════════════════════════════════════════════════════════

class TestNsgSshOpenRule:
    rule = NsgSshOpenRule()

    def test_ssh_open_standalone(self):
        violations = self.rule.evaluate(
            "azurerm_network_security_rule.bad_ssh",
            "azurerm_network_security_rule",
            {
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "destination_port_range": "22",
                "source_address_prefix": "0.0.0.0/0",
            },
        )
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH

    def test_ssh_open_wildcard_source(self):
        violations = self.rule.evaluate(
            "azurerm_network_security_rule.bad_ssh",
            "azurerm_network_security_rule",
            {
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "destination_port_range": "22",
                "source_address_prefix": "*",
            },
        )
        assert len(violations) == 1

    def test_ssh_restricted_source(self):
        violations = self.rule.evaluate(
            "azurerm_network_security_rule.good_ssh",
            "azurerm_network_security_rule",
            {
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "destination_port_range": "22",
                "source_address_prefix": "10.0.0.0/8",
            },
        )
        assert violations == []

    def test_ssh_deny_rule_ignored(self):
        violations = self.rule.evaluate(
            "azurerm_network_security_rule.deny_ssh",
            "azurerm_network_security_rule",
            {
                "direction": "Inbound",
                "access": "Deny",
                "protocol": "Tcp",
                "destination_port_range": "22",
                "source_address_prefix": "0.0.0.0/0",
            },
        )
        assert violations == []

    def test_port_range_includes_ssh(self):
        violations = self.rule.evaluate(
            "azurerm_network_security_rule.range",
            "azurerm_network_security_rule",
            {
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "destination_port_range": "20-25",
                "source_address_prefix": "*",
            },
        )
        assert len(violations) == 1

    def test_inline_nsg_rule(self):
        violations = self.rule.evaluate(
            "azurerm_network_security_group.bad_inline",
            "azurerm_network_security_group",
            {
                "name": "nsg-test",
                "security_rule": [
                    {
                        "name": "AllowSSH",
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "destination_port_range": "22",
                        "source_address_prefix": "*",
                    }
                ],
            },
        )
        assert len(violations) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Rule 4 — NAMING_CONVENTION
# ═══════════════════════════════════════════════════════════════════════════

class TestNamingConventionRule:
    rule = NamingConventionRule()

    def test_bad_rg_name(self):
        violations = self.rule.evaluate(
            "azurerm_resource_group.bad",
            "azurerm_resource_group",
            {"name": "DemoResourceGroup"},
        )
        assert len(violations) == 1
        assert violations[0].severity == Severity.MEDIUM
        assert violations[0].rule_id == "NAMING_CONVENTION"

    def test_good_rg_name(self):
        violations = self.rule.evaluate(
            "azurerm_resource_group.good",
            "azurerm_resource_group",
            {"name": "rg-my-app"},
        )
        assert violations == []

    def test_bad_storage_name(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.bad",
            "azurerm_storage_account",
            {"name": "DEMOPUBLICSTORAGE123"},
        )
        assert len(violations) == 1

    def test_good_storage_name(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.good",
            "azurerm_storage_account",
            {"name": "stmyapp001"},
        )
        assert violations == []

    def test_bad_vnet_name(self):
        violations = self.rule.evaluate(
            "azurerm_virtual_network.bad",
            "azurerm_virtual_network",
            {"name": "MyVNET"},
        )
        assert len(violations) == 1

    def test_unknown_type_passes(self):
        violations = self.rule.evaluate(
            "azurerm_cosmosdb_account.db",
            "azurerm_cosmosdb_account",
            {"name": "AnythingGoes"},
        )
        assert violations == []


# ═══════════════════════════════════════════════════════════════════════════
# Rule 5 — DISK_ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════

class TestDiskEncryptionRule:
    rule = DiskEncryptionRule()

    def test_no_encryption(self):
        violations = self.rule.evaluate(
            "azurerm_managed_disk.bad",
            "azurerm_managed_disk",
            {"name": "disk-test", "storage_account_type": "Standard_LRS"},
        )
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH

    def test_with_des_id(self):
        violations = self.rule.evaluate(
            "azurerm_managed_disk.good",
            "azurerm_managed_disk",
            {
                "name": "disk-test",
                "disk_encryption_set_id": "/subscriptions/xxx/...",
            },
        )
        assert violations == []

    def test_with_encryption_settings(self):
        violations = self.rule.evaluate(
            "azurerm_managed_disk.good2",
            "azurerm_managed_disk",
            {
                "name": "disk-test",
                "encryption_settings": [{"enabled": True}],
            },
        )
        assert violations == []

    def test_ignores_non_disk(self):
        violations = self.rule.evaluate(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"name": "sttest"},
        )
        assert violations == []


# ═══════════════════════════════════════════════════════════════════════════
# Full Engine Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestEngine:

    def test_demo_plan_has_violations(self):
        result = evaluate_plan(str(FIXTURES / "demo_plan.json"))
        assert result.resources_scanned == 6
        assert len(result.violations) > 0
        assert result.has_high_severity is True

    def test_compliant_plan_passes(self):
        result = evaluate_plan(str(FIXTURES / "compliant_plan.json"))
        assert result.resources_scanned == 4
        assert len(result.violations) == 0
        assert result.has_high_severity is False

    def test_demo_plan_catches_all_rule_types(self):
        result = evaluate_plan(str(FIXTURES / "demo_plan.json"))
        rule_ids = {v.rule_id for v in result.violations}
        assert "PUBLIC_STORAGE" in rule_ids
        assert "REQUIRED_TAGS" in rule_ids
        assert "NSG_SSH_OPEN" in rule_ids
        assert "NAMING_CONVENTION" in rule_ids
        assert "DISK_ENCRYPTION" in rule_ids

    def test_evaluate_plan_dict(self):
        plan = load_fixture("demo_plan.json")
        result = evaluate_plan_dict(plan)
        assert result.resources_scanned == 6
        assert len(result.violations) > 0


# ═══════════════════════════════════════════════════════════════════════════
# Reporter — Markdown Formatting
# ═══════════════════════════════════════════════════════════════════════════

class TestReporter:

    def test_format_markdown_with_violations(self):
        result = evaluate_plan(str(FIXTURES / "demo_plan.json"))
        md = format_markdown(result)
        assert "❌ Policy Gate — FAILED" in md
        assert "PUBLIC_STORAGE" in md
        assert "REQUIRED_TAGS" in md
        assert "blocked" in md.lower()

    def test_format_markdown_clean(self):
        result = evaluate_plan(str(FIXTURES / "compliant_plan.json"))
        md = format_markdown(result)
        assert "✅ Policy Gate — PASSED" in md
        assert "Good job" in md


# ═══════════════════════════════════════════════════════════════════════════
# Model Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestModels:

    def test_violation_to_dict(self):
        v = Violation(
            rule_id="TEST",
            resource_address="azurerm_resource_group.test",
            resource_type="azurerm_resource_group",
            severity=Severity.HIGH,
            message="test message",
            details={"key": "value"},
        )
        d = v.to_dict()
        assert d["rule_id"] == "TEST"
        assert d["severity"] == "HIGH"

    def test_policy_result_summary(self):
        result = PolicyResult(
            violations=[
                Violation("R1", "addr1", "type1", Severity.HIGH, "msg1"),
                Violation("R2", "addr2", "type2", Severity.MEDIUM, "msg2"),
            ],
            resources_scanned=5,
        )
        assert "5 resources" in result.summary
        assert "2 violation(s)" in result.summary
        assert result.has_high_severity is True

    def test_empty_result(self):
        result = PolicyResult()
        assert result.has_high_severity is False
        assert "0 violation(s)" in result.summary
