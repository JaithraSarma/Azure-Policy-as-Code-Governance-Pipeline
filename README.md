<<<<<<< HEAD
# Introduction 
TODO: Give a short introduction of your project. Let this section explain the objectives or the motivation behind this project. 

# Getting Started
TODO: Guide users through getting your code up and running on their own system. In this section you can talk about:
1.	Installation process
2.	Software dependencies
3.	Latest releases
4.	API references

# Build and Test
TODO: Describe and show how to build your code and run the tests. 

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 

If you want to learn more about creating good readme files then refer the following [guidelines](https://docs.microsoft.com/en-us/azure/devops/repos/git/create-a-readme?view=azure-devops). You can also seek inspiration from the below readme files:
- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)
=======
# Azure Policy Gate

> **A Terraform compliance engine that runs in Azure DevOps Pipelines, blocks non-compliant pull requests, and logs every violation to Azure Table Storage.**

[![Pipeline Status](https://img.shields.io/badge/pipeline-Azure%20DevOps-blue)](https://dev.azure.com)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-green)](https://python.org)
[![Terraform 1.5+](https://img.shields.io/badge/terraform-1.5%2B-purple)](https://terraform.io)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

---

## What It Does

Every time a pull request touches Terraform files, Azure Policy Gate:

1. **Runs `terraform plan`** and converts the output to JSON
2. **Evaluates 5 built-in policy rules** against every planned resource change
3. **Posts a formatted violation report** as a comment on the PR
4. **Fails the pipeline** and blocks the PR when HIGH severity violations are found
5. **Logs every violation** to Azure Table Storage with timestamp, PR number, repository, and outcome

```
PR Created → Pipeline Triggers → terraform plan → Policy Engine → PR Comment + Table Log
                                                        │
                                                        ├── PASS → PR can merge ✅
                                                        └── FAIL → PR blocked  ❌
```

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                        Azure DevOps                               │
│  ┌─────────────┐    ┌───────────────┐    ┌─────────────────────┐ │
│  │ Pull Request │───▶│   Pipeline    │───▶│  Policy Engine (Py) │ │
│  │  (Terraform) │    │ (YAML stages) │    │  5 built-in rules   │ │
│  └─────────────┘    └───────┬───────┘    └─────────┬───────────┘ │
│                             │                       │             │
│                     ┌───────▼───────┐       ┌───────▼──────────┐ │
│                     │ terraform plan│       │   PR Comment     │ │
│                     │   → JSON      │       │   (REST API)     │ │
│                     └───────────────┘       └──────────────────┘ │
└───────────────────────────────────────────────┬───────────────────┘
                                                │
                                        ┌───────▼──────────┐
                                        │  Azure Storage   │
                                        │  ┌─────────────┐ │
                                        │  │ Blob: tfstate│ │
                                        │  │ (remote state│ │
                                        │  └─────────────┘ │
                                        │  ┌─────────────┐ │
                                        │  │ Table:       │ │
                                        │  │ Violations   │ │
                                        │  │ (audit log)  │ │
                                        │  └─────────────┘ │
                                        └──────────────────┘
```

---

## Policy Rules

| # | Rule ID | What It Checks | Severity | Trigger |
|---|---------|----------------|----------|---------|
| 1 | `PUBLIC_STORAGE` | Storage accounts with public network access, open network rules, or public blob access | **HIGH** | `azurerm_storage_account` with `public_network_access_enabled = true`, `allow_nested_items_to_be_public = true`, or `network_rules.default_action = "Allow"` |
| 2 | `REQUIRED_TAGS` | Missing mandatory tags: `owner`, `env`, `project`, `cost-centre` | **HIGH** | Any `azurerm_*` resource missing one or more required tags |
| 3 | `NSG_SSH_OPEN` | NSG rules allowing SSH (port 22) from the internet | **HIGH** | `azurerm_network_security_rule` or inline NSG rules with `source_address_prefix = "0.0.0.0/0"` or `"*"` and `destination_port_range` including 22 |
| 4 | `NAMING_CONVENTION` | Resource names violating Cloud Adoption Framework naming patterns | **MEDIUM** | Names not matching expected prefixes: `rg-`, `st`, `vnet-`, `nsg-`, `disk-`, `kv-`, `vm-`, `pip-`, `snet-` |
| 5 | `DISK_ENCRYPTION` | Managed disks without encryption configured | **HIGH** | `azurerm_managed_disk` missing both `disk_encryption_set_id` and `encryption_settings` |

### Severity Behaviour

- **HIGH** → Pipeline fails, PR is blocked from merging
- **MEDIUM** → Warning posted in PR comment, pipeline still passes
- **LOW** → Informational, logged but does not affect pipeline

---

## Repository Structure

```
azure-policy-gate/
├── azure-pipelines.yml              # Azure DevOps pipeline definition
├── requirements.txt                 # Python dependencies
├── .gitignore
│
├── terraform/
│   ├── backend/                     # Backend infrastructure (state + table)
│   │   ├── main.tf                  #   Storage Account, blob container, table
│   │   ├── variables.tf
│   │   └── outputs.tf
│   │
│   └── demo/                        # Demo infrastructure (intentionally bad)
│       ├── main.tf                  #   Non-compliant resources for testing
│       ├── providers.tf
│       ├── backend.tf               #   Remote state configuration
│       ├── variables.tf
│       └── outputs.tf
│
├── policy_engine/                   # Python policy engine
│   ├── __init__.py
│   ├── models.py                    #   Violation, PolicyResult data classes
│   ├── engine.py                    #   Plan parser + rule orchestrator
│   ├── reporter.py                  #   PR comment + Table Storage writer
│   ├── main.py                      #   CLI entry point
│   │
│   └── rules/                       #   Policy rule implementations
│       ├── __init__.py              #     Rule registry
│       ├── base.py                  #     Abstract base class
│       ├── public_storage.py        #     Rule 1: Public storage detection
│       ├── required_tags.py         #     Rule 2: Required tag validation
│       ├── nsg_ssh_open.py          #     Rule 3: Open SSH detection
│       ├── naming_convention.py     #     Rule 4: Naming convention check
│       └── disk_encryption.py       #     Rule 5: Disk encryption check
│
├── tests/                           # Test suite
│   ├── test_rules.py                #   30+ unit & integration tests
│   └── fixtures/
│       ├── demo_plan.json           #   Non-compliant plan fixture
│       └── compliant_plan.json      #   Clean plan fixture
│
├── docs/
│   └── SETUP_GUIDE.md               # Step-by-step configuration guide
│
└── README.md                        # This file
```

---

## Quick Start

### Prerequisites

- Azure subscription
- Azure CLI (v2.50+)
- Terraform (v1.5+)
- Python (3.10+)
- Azure DevOps organisation

### 1. Clone and Install

```bash
git clone <your-repo-url>
cd azure-policy-gate

# Python dependencies
python -m pip install -r requirements.txt
```

### 2. Run Tests Locally

```bash
pytest tests/ -v
```

Expected output:

```
tests/test_rules.py::TestPublicStorageRule::test_public_access_enabled       PASSED
tests/test_rules.py::TestPublicStorageRule::test_nested_public_access        PASSED
tests/test_rules.py::TestPublicStorageRule::test_network_rules_allow         PASSED
tests/test_rules.py::TestPublicStorageRule::test_compliant_storage           PASSED
tests/test_rules.py::TestPublicStorageRule::test_ignores_non_storage         PASSED
tests/test_rules.py::TestRequiredTagsRule::test_missing_all_tags             PASSED
tests/test_rules.py::TestRequiredTagsRule::test_partial_tags                 PASSED
tests/test_rules.py::TestRequiredTagsRule::test_all_tags_present             PASSED
tests/test_rules.py::TestRequiredTagsRule::test_ignores_non_azure_types      PASSED
tests/test_rules.py::TestNsgSshOpenRule::test_ssh_open_standalone            PASSED
tests/test_rules.py::TestNsgSshOpenRule::test_ssh_open_wildcard_source       PASSED
tests/test_rules.py::TestNsgSshOpenRule::test_ssh_restricted_source          PASSED
tests/test_rules.py::TestNsgSshOpenRule::test_ssh_deny_rule_ignored          PASSED
tests/test_rules.py::TestNsgSshOpenRule::test_port_range_includes_ssh        PASSED
tests/test_rules.py::TestNsgSshOpenRule::test_inline_nsg_rule                PASSED
tests/test_rules.py::TestNamingConventionRule::test_bad_rg_name              PASSED
tests/test_rules.py::TestNamingConventionRule::test_good_rg_name             PASSED
tests/test_rules.py::TestNamingConventionRule::test_bad_storage_name         PASSED
tests/test_rules.py::TestNamingConventionRule::test_good_storage_name        PASSED
tests/test_rules.py::TestNamingConventionRule::test_bad_vnet_name            PASSED
tests/test_rules.py::TestNamingConventionRule::test_unknown_type_passes      PASSED
tests/test_rules.py::TestDiskEncryptionRule::test_no_encryption              PASSED
tests/test_rules.py::TestDiskEncryptionRule::test_with_des_id                PASSED
tests/test_rules.py::TestDiskEncryptionRule::test_with_encryption_settings   PASSED
tests/test_rules.py::TestDiskEncryptionRule::test_ignores_non_disk           PASSED
tests/test_rules.py::TestEngine::test_demo_plan_has_violations               PASSED
tests/test_rules.py::TestEngine::test_compliant_plan_passes                  PASSED
tests/test_rules.py::TestEngine::test_demo_plan_catches_all_rule_types       PASSED
tests/test_rules.py::TestEngine::test_evaluate_plan_dict                     PASSED
tests/test_rules.py::TestReporter::test_format_markdown_with_violations      PASSED
tests/test_rules.py::TestReporter::test_format_markdown_clean                PASSED
tests/test_rules.py::TestModels::test_violation_to_dict                      PASSED
tests/test_rules.py::TestModels::test_policy_result_summary                  PASSED
tests/test_rules.py::TestModels::test_empty_result                           PASSED

34 passed in 0.12s
```

### 3. Run Against a Plan Locally

```bash
# Using the included test fixture
python -m policy_engine.main tests/fixtures/demo_plan.json
```

Expected output:

```
════════════════════════════════════════════════════════════
  Azure Policy Gate — Evaluating tests/fixtures/demo_plan.json
════════════════════════════════════════════════════════════

Scanned 6 resources — 14 violation(s) found (HIGH: 11, MEDIUM: 4, LOW: 0)

  🔴 [PUBLIC_STORAGE] azurerm_storage_account.demo
      Storage account has public_network_access_enabled = true. ...

  🔴 [REQUIRED_TAGS] azurerm_resource_group.demo
      Resource is missing required tag(s): cost-centre, owner. ...

  🔴 [NSG_SSH_OPEN] azurerm_network_security_rule.allow_ssh
      NSG rule allows inbound SSH (port 22) from the public internet. ...

  🟡 [NAMING_CONVENTION] azurerm_resource_group.demo
      Resource name 'DemoResourceGroup' does not match the required naming convention ...

  🔴 [DISK_ENCRYPTION] azurerm_managed_disk.demo
      Managed disk does not have encryption configured. ...

⛔ HIGH severity violations detected — pipeline FAILED.
```

### 4. Deploy Backend Infrastructure

```bash
cd terraform/backend
terraform init
terraform apply -auto-approve
```

### 5. Configure Azure DevOps

Follow the detailed instructions in [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md):

1. Create a Service Principal
2. Create a Service Connection in Azure DevOps
3. Add pipeline variables (`ARM_*`, `AZURE_STORAGE_CONNECTION_STRING`)
4. Create the pipeline from `azure-pipelines.yml`
5. Set up branch protection on `main`

---

## How the Pipeline Works

```yaml
PR Created/Updated (touching terraform/**)
    │
    ▼
┌─────────────────────────────────────┐
│  Stage 1: Terraform Plan            │
│  ├── terraform init                 │
│  ├── terraform plan -out=tfplan.bin  │
│  ├── terraform show -json → JSON    │
│  └── Publish artifact               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Stage 2: Policy Check              │
│  ├── Download plan artifact         │
│  ├── pip install requirements       │
│  ├── python -m policy_engine.main   │
│  │   ├── Parse plan JSON            │
│  │   ├── Run 5 policy rules         │
│  │   ├── Post PR comment            │
│  │   ├── Log to Table Storage       │
│  │   └── Exit 0 (pass) or 1 (fail) │
│  └── Publish report artifact        │
└─────────────────────────────────────┘
```

---

## PR Comment Example

When violations are found, the engine posts a comment like this:

> ## ❌ Policy Gate — FAILED
>
> **Scanned 6 resources — 14 violation(s) found (HIGH: 11, MEDIUM: 4, LOW: 0)**
>
> | # | Severity | Rule | Resource | Message |
> |---|----------|------|----------|---------|
> | 1 | 🔴 HIGH | `PUBLIC_STORAGE` | `azurerm_storage_account.demo` | Storage account has public_network_access_enabled = true... |
> | 2 | 🔴 HIGH | `REQUIRED_TAGS` | `azurerm_resource_group.demo` | Resource is missing required tag(s): cost-centre, owner... |
> | 3 | 🔴 HIGH | `NSG_SSH_OPEN` | `azurerm_network_security_rule.allow_ssh` | NSG rule allows inbound SSH (port 22) from the public internet... |
> | 4 | 🟡 MEDIUM | `NAMING_CONVENTION` | `azurerm_resource_group.demo` | Resource name 'DemoResourceGroup' does not match... |
> | 5 | 🔴 HIGH | `DISK_ENCRYPTION` | `azurerm_managed_disk.demo` | Managed disk does not have encryption configured... |
>
> ⛔ **This PR is blocked.** Fix all HIGH-severity violations before merging.

---

## Table Storage Schema

Every violation is persisted to the `PolicyViolations` table:

| Column | Type | Description |
|--------|------|-------------|
| `PartitionKey` | string | PR number (or `"local"` for local runs) |
| `RowKey` | string | `<run-id>-<index>` |
| `Timestamp_UTC` | string | ISO 8601 timestamp |
| `PRNumber` | string | Pull request number |
| `Repository` | string | Repository name |
| `Outcome` | string | `PASS` or `FAIL` |
| `RuleId` | string | Rule identifier (e.g., `PUBLIC_STORAGE`) |
| `ResourceAddress` | string | Terraform resource address |
| `ResourceType` | string | Resource type (e.g., `azurerm_storage_account`) |
| `Severity` | string | `HIGH`, `MEDIUM`, or `LOW` |
| `Message` | string | Human-readable violation description |
| `Details` | string | JSON-encoded additional details |

---

## Adding New Rules

The engine is designed for extensibility. To add a new rule:

### Step 1: Create the Rule File

Create `policy_engine/rules/my_new_rule.py`:

```python
from typing import Any
from policy_engine.models import Severity, Violation
from policy_engine.rules.base import PolicyRule


class MyNewRule(PolicyRule):

    @property
    def rule_id(self) -> str:
        return "MY_NEW_RULE"

    @property
    def description(self) -> str:
        return "Description of what this rule checks."

    def evaluate(
        self,
        resource_address: str,
        resource_type: str,
        resource_values: dict[str, Any],
    ) -> list[Violation]:
        # Only check specific resource types
        if resource_type != "azurerm_some_resource":
            return []

        # Your check logic here
        if some_condition_is_violated(resource_values):
            return [
                Violation(
                    rule_id=self.rule_id,
                    resource_address=resource_address,
                    resource_type=resource_type,
                    severity=Severity.HIGH,
                    message="What went wrong and how to fix it.",
                    details={"key": "value"},
                )
            ]
        return []
```

### Step 2: Register the Rule

Edit `policy_engine/rules/__init__.py`:

```python
from policy_engine.rules.my_new_rule import MyNewRule

ALL_RULES: list[PolicyRule] = [
    # ... existing rules ...
    MyNewRule(),
]
```

### Step 3: Add Tests

Add test cases in `tests/test_rules.py` following the existing pattern.

---

## Ideas for Extension

Here are concrete enhancements you could add to this project:

### Additional Policy Rules

| Rule | What It Checks | Severity |
|------|----------------|----------|
| `KEY_VAULT_SOFT_DELETE` | Key Vault without soft-delete or purge protection | HIGH |
| `SQL_FIREWALL_OPEN` | SQL Server firewall rules allowing 0.0.0.0 | HIGH |
| `HTTPS_ONLY` | App Service / Function App without HTTPS-only | HIGH |
| `PRIVATE_ENDPOINT` | Database resources without private endpoints | MEDIUM |
| `RESOURCE_LOCKS` | Production resources without delete locks | MEDIUM |
| `LOG_ANALYTICS` | Resources without diagnostic settings | LOW |
| `GEO_REDUNDANCY` | Storage/DB without geo-redundant replication | MEDIUM |
| `WAF_ENABLED` | Application Gateway without WAF | HIGH |

### Platform Enhancements

| Enhancement | Description |
|-------------|-------------|
| **Policy-as-Code config** | Load rules and thresholds from a YAML config file (`policy.yml`) so teams can customise without touching Python |
| **Exemptions system** | Allow teams to exempt specific resources from specific rules with documented justification (`# policy:ignore RULE_ID`) |
| **Trend dashboard** | Build a Power BI or Grafana dashboard on top of Table Storage to track violation trends per team/project |
| **Slack/Teams notifications** | Send violation summaries to a Teams channel via incoming webhook |
| **Cost estimation** | Integrate `infracost` to add estimated monthly cost to the PR comment |
| **Multi-repo support** | Publish the engine as a PyPI package and consume it from multiple repos |
| **Caching** | Cache terraform plan output between pipeline runs when no Terraform files changed |
| **SARIF output** | Generate SARIF format for integration with GitHub Advanced Security / Azure DevOps code scanning |

### Security Hardening

| Enhancement | Description |
|-------------|-------------|
| **Managed Identity** | Replace Service Principal with pipeline Managed Identity |
| **Key Vault secrets** | Store pipeline secrets in Azure Key Vault instead of pipeline variables |
| **SAS tokens** | Use short-lived SAS tokens for Table Storage writes |
| **Audit trail** | Add immutable logging with Azure Immutable Blob Storage |

---

## Environment Variables Reference

| Variable | Used By | Required | Description |
|----------|---------|----------|-------------|
| `ARM_SUBSCRIPTION_ID` | Terraform | Yes | Azure subscription ID |
| `ARM_CLIENT_ID` | Terraform | Yes | Service Principal client ID |
| `ARM_CLIENT_SECRET` | Terraform | Yes | Service Principal secret |
| `ARM_TENANT_ID` | Terraform | Yes | Azure AD tenant ID |
| `AZURE_STORAGE_CONNECTION_STRING` | Reporter | Yes* | Connection string for Table Storage |
| `VIOLATIONS_TABLE_NAME` | Reporter | No | Table name (default: `PolicyViolations`) |
| `SYSTEM_ACCESSTOKEN` | Reporter | Auto | Azure DevOps OAuth token (auto-set in pipeline) |
| `SYSTEM_PULLREQUEST_PULLREQUESTID` | Reporter | Auto | PR number (auto-set in pipeline) |
| `POLICY_REPORT_PATH` | Main | No | Output path for markdown report (default: `policy-report.md`) |

*Required only when Table Storage logging is desired. The engine works without it.

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **CI/CD** | Azure DevOps Pipelines | Pipeline orchestration, PR integration |
| **IaC** | Terraform (AzureRM) | Infrastructure definitions + remote state |
| **Policy Engine** | Python 3.11 | Rule evaluation, reporting |
| **State Storage** | Azure Blob Storage | Terraform remote state backend |
| **Audit Log** | Azure Table Storage | Violation record persistence |
| **PR Integration** | Azure DevOps REST API | Automated PR commenting |

No external tools. No third-party services. Pure Azure + Terraform + Python.

---

## License

MIT — see [LICENSE](LICENSE) for details.
>>>>>>> c542ca5 (docs: add comprehensive README with architecture, rules, and extension guide)
