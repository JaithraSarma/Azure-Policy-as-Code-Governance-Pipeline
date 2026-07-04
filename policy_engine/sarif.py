"""
SARIF module for generating SARIF 2.1.0 format reports.
"""

import json
from typing import Any
from policy_engine.models import PolicyResult, Severity


def format_sarif(result: PolicyResult) -> str:
    """
    Generate a SARIF 2.1.0 formatted JSON string from a PolicyResult.
    """
    from policy_engine.rules import ALL_RULES

    # Build rules section
    rules_list = []
    for rule in ALL_RULES:
        rules_list.append({
            "id": rule.rule_id,
            "shortDescription": {
                "text": rule.description
            }
        })

    # Map severities to SARIF levels
    severity_map = {
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note"
    }

    # Build results section
    results_list = []
    for violation in result.violations:
        level = severity_map.get(violation.severity, "warning")

        res_obj: dict[str, Any] = {
            "ruleId": violation.rule_id,
            "level": level,
            "message": {
                "text": violation.message
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "terraform/demo/main.tf"
                        }
                    },
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": violation.resource_address,
                            "kind": "resource"
                        }
                    ]
                }
            ]
        }

        # Embed suppression metadata if violation is exempted
        if violation.exempted:
            res_obj["suppressions"] = [
                {
                    "kind": "external",
                    "justification": violation.exemption_reason or "Suppressed via exemptions.yml"
                }
            ]

        results_list.append(res_obj)

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Azure Policy Gate",
                        "rules": rules_list
                    }
                },
                "results": results_list
            }
        ]
    }

    return json.dumps(sarif_doc, indent=2)
