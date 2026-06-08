# Azure Policy Gate — Comprehensive Theory & Interview Guide

> This document covers all theoretical knowledge needed to explain, defend, and extend this project in job interviews, college vivas, and technical discussions.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Core Concepts](#2-core-concepts)
3. [Architecture Deep Dive](#3-architecture-deep-dive)
4. [Terraform Fundamentals](#4-terraform-fundamentals)
5. [Azure DevOps Pipelines](#5-azure-devops-pipelines)
6. [Python Policy Engine Design](#6-python-policy-engine-design)
7. [Azure Storage Services](#7-azure-storage-services)
8. [Security & Authentication](#8-security--authentication)
9. [Policy-as-Code Philosophy](#9-policy-as-code-philosophy)
10. [Interview Q&A Bank](#10-interview-qa-bank)
11. [Viva Walkthrough Script](#11-viva-walkthrough-script)
12. [Debugging & Troubleshooting Journey](#12-debugging--troubleshooting-journey)

---

## 1. Project Overview

### What Is Azure Policy Gate?

Azure Policy Gate is a **compliance enforcement system** that automatically scans Terraform infrastructure plans for policy violations before they are deployed. It integrates directly into the Azure DevOps pull request workflow — acting as an automated code reviewer that catches security misconfigurations, governance gaps, and naming standard violations.

### Why Does This Matter?

In enterprise environments, infrastructure misconfigurations are the #1 cause of cloud security breaches. Manual code review cannot catch every issue. Policy Gate automates this:

| Without Policy Gate | With Policy Gate |
|---|---|
| Storage accounts accidentally made public | Automatically detected and blocked |
| Missing cost tracking tags | PR blocked until tags added |
| SSH open to the internet | Flagged before deployment |
| Non-standard resource names | Caught at PR time |
| Unencrypted disks | Blocked before provisioning |

### The End-to-End Flow

```
Developer writes Terraform → Creates PR → Pipeline triggers automatically
    → terraform plan → JSON conversion → Python policy engine evaluates
    → Violations posted as PR comment → HIGH severity = pipeline fails
    → PR blocked from merging → Violations logged to Table Storage
```

---

## 2. Core Concepts

### Infrastructure as Code (IaC)

IaC means managing infrastructure through machine-readable definition files rather than manual console clicks. Benefits:
- **Version control** — track every change via Git
- **Reproducibility** — identical environments every time
- **Peer review** — PRs enable team review of infra changes
- **Automation** — CI/CD pipelines can deploy automatically

Terraform is a **declarative** IaC tool — you describe the desired state, and Terraform figures out how to get there.

### Shift-Left Security

"Shift left" means catching problems earlier in the development lifecycle. Traditional approach: deploy first, audit later. Shift-left: catch violations **before deployment**, at PR time. Azure Policy Gate implements shift-left by scanning plans before `terraform apply` runs.

### GitOps & Pull Request Workflows

GitOps treats Git as the single source of truth. All changes go through pull requests, which enables:
- Code review by peers
- Automated CI/CD validation
- Branch protection (block merge until checks pass)
- Audit trail of who changed what and when

### Policy-as-Code

Instead of documenting policies in Word docs that nobody reads, encode them as executable code. Benefits:
- **Automated enforcement** — no human can bypass them
- **Testable** — unit tests prove rules work correctly
- **Versioned** — rules evolve alongside infrastructure
- **Auditable** — every violation is logged with context

---

## 3. Architecture Deep Dive

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                   Azure DevOps                           │
│                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐ │
│  │    PR     │───▶│   Pipeline   │───▶│ Policy Engine │ │
│  │(Terraform)│    │  (2 stages)  │    │  (Python)     │ │
│  └──────────┘    └──────┬───────┘    └──────┬────────┘ │
│                         │                    │          │
│                  ┌──────▼───────┐    ┌───────▼───────┐ │
│                  │ terraform    │    │  PR Comment   │ │
│                  │ plan → JSON  │    │  (REST API)   │ │
│                  └──────────────┘    └───────────────┘ │
└───────────────────────────────────────┬─────────────────┘
                                        │
                                ┌───────▼───────┐
                                │ Azure Storage │
                                │  Blob: state  │
                                │  Table: audit │
                                └───────────────┘
```

### Data Flow

1. **Developer** pushes Terraform changes to a feature branch
2. **PR creation** triggers the Azure DevOps pipeline
3. **Stage 1** runs `terraform plan` and exports JSON
4. **Stage 2** feeds JSON to the Python policy engine
5. **Engine** iterates over every resource, runs 5 rules
6. **Reporter** posts markdown comment on PR via REST API
7. **Reporter** logs violations to Azure Table Storage
8. **Exit code** determines pipeline pass/fail
9. **Branch policy** blocks merge if pipeline failed

### Why Two Stages?

- **Separation of concerns** — Terraform operations vs. policy evaluation
- **Artifact passing** — plan JSON is published as a pipeline artifact between stages
- **Independent failure** — if Terraform plan fails, policy check doesn't run
- **Reusability** — policy check stage could be reused across repos

---

## 4. Terraform Fundamentals

### What Is Terraform?

Terraform is HashiCorp's IaC tool that uses **HCL** (HashiCorp Configuration Language) to define cloud resources declaratively. It works with 3000+ providers (AWS, Azure, GCP, etc.).

### Terraform Workflow

```
terraform init    →  Download providers, configure backend
terraform plan    →  Compare desired state vs. actual state, show diff
terraform apply   →  Execute the plan, create/update/delete resources
terraform destroy →  Remove all managed resources
```

### Key Concepts Used in This Project

**Remote State Backend**
```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-policy-gate-backend"
    storage_account_name = "<storage_account>"
    container_name       = "tfstate"
    key                  = "demo.terraform.tfstate"
  }
}
```
- State files track what Terraform manages
- Remote backends enable team collaboration (no local state conflicts)
- Azure Blob Storage is used as the backend

**Terraform Plan JSON**

`terraform show -json tfplan.bin` produces a JSON representation of the plan. Key structure:
```json
{
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "azurerm_storage_account.demo",
          "type": "azurerm_storage_account",
          "values": {
            "public_network_access_enabled": true,
            "tags": { ... }
          }
        }
      ]
    }
  }
}
```

The policy engine parses this JSON and evaluates each resource's `values` against rules.

**Resource Types Used**
| Type | Purpose |
|------|---------|
| `azurerm_resource_group` | Logical container for Azure resources |
| `azurerm_storage_account` | Object/blob/table/queue storage |
| `azurerm_storage_container` | Blob container within storage account |
| `azurerm_storage_table` | NoSQL table storage |
| `azurerm_network_security_group` | Network firewall rules |
| `azurerm_network_security_rule` | Individual NSG rule |
| `azurerm_managed_disk` | VM disk storage |
| `azurerm_virtual_network` | Virtual network |

---

## 5. Azure DevOps Pipelines

### YAML Pipelines

Azure DevOps supports YAML-based pipeline definitions checked into source control. Structure:

```yaml
trigger: ...          # When to run (push, PR, schedule)
pool: ...             # Agent pool (ubuntu-latest, windows-latest)
variables: ...        # Pipeline variables and variable groups
stages:               # Ordered list of stages
  - stage: Build
    jobs:
      - job: Compile
        steps:
          - script: echo "hello"
```

### PR Triggers

```yaml
pr:
  branches:
    include: [main]
  paths:
    include: [terraform/**]
```
This means: trigger on PRs targeting `main` that modify files under `terraform/`.

### Variable Groups

Variables stored in **Pipelines → Library → Variable groups**. Referenced in YAML:
```yaml
variables:
  - group: policy-gate-vars
```
Secret variables (like `ARM_CLIENT_SECRET`) are encrypted and masked in logs.

### Pipeline Artifacts

```yaml
- publish: $(TF_WORKING_DIR)/tfplan.json
  artifact: tfplan

- download: current
  artifact: tfplan
```
Artifacts pass data between stages. Stage 1 publishes the plan JSON; Stage 2 downloads it.

### System Variables

Azure DevOps auto-populates variables in PR context:
| Variable | Value |
|----------|-------|
| `System.PullRequest.PullRequestId` | PR number |
| `System.AccessToken` | OAuth token for REST API |
| `Build.Repository.Name` | Repository name |
| `System.TeamFoundationCollectionUri` | Organization URL |

### Branch Policies

Under **Repos → Branches → Branch policies**:
- **Build Validation** — require a pipeline to pass before merge
- **Minimum reviewers** — require human approval
- **Comment resolution** — all review comments must be resolved

---

## 6. Python Policy Engine Design

### Design Patterns Used

**Strategy Pattern** — Each rule is a strategy that implements the same interface (`PolicyRule.evaluate()`). The engine doesn't know or care about specific rules — it just iterates and calls `evaluate()`.

**Template Method** — The abstract base class defines the contract; each rule fills in the specifics.

**Registry Pattern** — All rules are registered in `ALL_RULES` list in `__init__.py`. Adding a rule = create file + add to list.

### Class Hierarchy

```
PolicyRule (abstract base)
├── PublicStorageRule
├── RequiredTagsRule
├── NsgSshOpenRule
├── NamingConventionRule
└── DiskEncryptionRule
```

### How the Engine Works

```python
def evaluate_plan(plan_path):
    plan = json.load(open(plan_path))
    resources = extract_resources(plan)      # Parse planned_values
    violations = []
    for resource in resources:
        for rule in ALL_RULES:
            violations += rule.evaluate(     # Strategy pattern
                resource.address,
                resource.type,
                resource.values
            )
    return PolicyResult(violations)
```

### Severity Model

```python
class Severity(Enum):
    LOW = "LOW"        # Informational only
    MEDIUM = "MEDIUM"  # Warning, doesn't block
    HIGH = "HIGH"      # Blocks pipeline, blocks PR merge
```

The CLI exit code depends on severity:
- Any HIGH → `exit(1)` → pipeline fails → PR blocked
- No HIGH → `exit(0)` → pipeline passes → PR can merge

### Rule Implementation Example

```python
class PublicStorageRule(PolicyRule):
    @property
    def rule_id(self): return "PUBLIC_STORAGE"

    def evaluate(self, address, type, values):
        if type != "azurerm_storage_account":
            return []
        if values.get("public_network_access_enabled") == True:
            return [Violation(
                rule_id="PUBLIC_STORAGE",
                severity=Severity.HIGH,
                message="Storage account is publicly accessible"
            )]
        return []
```

### Reporter Architecture

Two output channels:
1. **PR Comment** — POST to Azure DevOps REST API (`/pullRequests/{id}/threads`)
2. **Table Storage** — upsert entities via `azure-data-tables` SDK

Both are optional — the engine works without either (graceful degradation with warning messages).

---

## 7. Azure Storage Services

### Blob Storage
- Used for **Terraform remote state**
- Container: `tfstate`, access: private
- Supports locking to prevent concurrent state modifications

### Table Storage
- Used for **violation audit log**
- NoSQL key-value store with PartitionKey + RowKey
- Schema: PR number, rule ID, resource, severity, message, timestamp, outcome
- Extremely cheap (~$0.00036 per 10,000 transactions)
- Queryable via Azure CLI, Storage Explorer, or REST API

### Why Table Storage over SQL/Cosmos?
- **Cost** — orders of magnitude cheaper
- **Simplicity** — no schema migrations, no connection pooling
- **Sufficient** — audit logs don't need complex queries or joins
- **Native SDK** — `azure-data-tables` package, 3 lines to write an entity

---

## 8. Security & Authentication

### Service Principal

An Azure AD identity for automated processes. Created via:
```bash
az ad sp create-for-rbac --name "sp-policy-gate-pipeline" --role Contributor
```

Components:
| Component | What It Is |
|-----------|-----------|
| Client ID (appId) | Username equivalent |
| Client Secret (password) | Password equivalent |
| Tenant ID | Azure AD directory |
| Subscription ID | Which Azure subscription |

### How Auth Flows in the Pipeline

```
Pipeline → ARM_* env vars → Terraform AzureRM provider → Azure API
Pipeline → System.AccessToken → Azure DevOps REST API → PR comment
Pipeline → Connection String → azure-data-tables SDK → Table Storage
```

### Security Best Practices Implemented
- Secrets stored as pipeline secret variables (masked in logs)
- Variable group centralizes secret management
- Storage Account has `allow_nested_items_to_be_public = false`
- State container is private access only
- TLS 1.2 enforced on storage account

---

## 9. Policy-as-Code Philosophy

### What Is Policy-as-Code?

Converting organizational compliance requirements into executable, testable, version-controlled code. Instead of "all storage accounts must be private" in a document → encode it as a rule that automatically blocks violations.

### Industry Tools Comparison

| Tool | Vendor | Language | Approach |
|------|--------|----------|----------|
| **Azure Policy Gate** (this project) | Custom | Python | Pre-deployment scan of Terraform plans |
| **Azure Policy** | Microsoft | JSON | Runtime enforcement on Azure resources |
| **OPA/Rego** | CNCF | Rego | General-purpose policy engine |
| **HashiCorp Sentinel** | HashiCorp | Sentinel | Terraform Enterprise/Cloud only |
| **Checkov** | Bridgecrew | Python | Static analysis of IaC files |
| **tfsec** | Aqua Security | Go | Terraform-specific security scanner |

### Why Build Custom Instead of Using OPA/Sentinel?

1. **Project constraint** — no external tools
2. **Full control** — custom rules, custom reporting, custom integrations
3. **Azure-native** — direct Table Storage and DevOps API integration
4. **Simpler** — no Rego/Sentinel learning curve
5. **Extensible** — adding rules is adding a Python class

---

## 10. Interview Q&A Bank

### Architecture Questions

**Q: Walk me through what happens when a developer creates a PR.**
A: The PR triggers an Azure DevOps pipeline (via `pr:` trigger on `terraform/**` paths). Stage 1 runs `terraform init` and `terraform plan`, converting the plan to JSON. The JSON artifact is passed to Stage 2, where the Python policy engine parses every planned resource change and evaluates it against 5 rules. Violations are posted as a PR comment via the Azure DevOps REST API and logged to Azure Table Storage. If any HIGH severity violations exist, the engine exits with code 1, failing the pipeline. Branch protection prevents merging until the pipeline passes.

**Q: Why did you choose a two-stage pipeline?**
A: Separation of concerns. Stage 1 handles Terraform operations (requires Azure credentials), Stage 2 handles policy evaluation (requires only the plan JSON). This enables artifact-based data passing, independent failure modes, and potential reuse of the policy check stage across repositories.

**Q: How does the engine parse the Terraform plan?**
A: It reads the JSON output of `terraform show -json`. The engine extracts resources from `planned_values.root_module.resources` (and child modules). For each resource, it gets the `address`, `type`, and `values` dict, then passes these to every registered rule's `evaluate()` method.

**Q: How do you handle the PR comment integration?**
A: The reporter uses the Azure DevOps REST API. It constructs a markdown table with all violations and POSTs it to `/pullRequests/{id}/threads` using the `System.AccessToken` OAuth token that Azure DevOps automatically provides in pipeline context.

### Design Questions

**Q: How would you add a 6th rule?**
A: Create a new Python file in `policy_engine/rules/` (e.g., `key_vault_soft_delete.py`), subclass `PolicyRule`, implement the `rule_id`, `description`, and `evaluate()` methods, then add an instance to `ALL_RULES` in `__init__.py`. Add tests. One-file change + registration.

**Q: Why Python over Go or Rust?**
A: Python has first-class Azure SDK support (`azure-data-tables`), is widely understood, enables rapid iteration, and matches the project constraint of no external tools. The policy engine runs once per PR — it doesn't need Go/Rust performance.

**Q: What design patterns did you use?**
A: Strategy pattern (each rule is an interchangeable strategy), Template method (abstract base class defines the contract), Registry pattern (ALL_RULES list), and Builder pattern (PolicyResult accumulates violations).

**Q: How do you handle false positives?**
A: Currently, the engine evaluates every `azurerm_*` resource. An exemption system could be added via inline Terraform comments (`# policy:ignore RULE_ID`) or a YAML config file that maps resource addresses to exempted rules.

### Security Questions

**Q: How are credentials managed?**
A: Service Principal credentials are stored as secret variables in an Azure DevOps variable group (`policy-gate-vars`). They're encrypted at rest and masked in pipeline logs. The `System.AccessToken` for PR commenting is auto-provided by Azure DevOps.

**Q: Why not use Managed Identity?**
A: Azure DevOps Microsoft-hosted agents don't support Managed Identity out of the box. Self-hosted agents with Azure VM identity could enable this. SP key auth was the pragmatic choice.

**Q: What if someone bypasses the policy gate?**
A: Branch protection makes the pipeline a required check — the merge button is disabled until it passes. Admins can override, but that's logged. Additionally, Azure Policy (runtime) can provide a second layer of defense.

### Terraform Questions

**Q: Why use remote state?**
A: Local state files can't be shared across a team or pipeline. Remote state in Azure Blob Storage enables collaboration, state locking (prevents concurrent modifications), and backup.

**Q: What's the difference between `terraform plan` and `terraform apply`?**
A: `plan` is a dry run — it shows what would change without modifying anything. `apply` executes the changes. Policy Gate only runs `plan` — it never applies infrastructure changes.

**Q: Why does the demo infrastructure fail validation?**
A: By design. The demo resources have intentional violations (public storage, missing tags, open SSH, bad names, no encryption) so the policy engine has real violations to detect. This proves the system works.

---

## 11. Viva Walkthrough Script

### Opening Statement (30 seconds)
"Azure Policy Gate is a compliance enforcement system for Terraform infrastructure. It integrates into the Azure DevOps pull request workflow to automatically scan Terraform plans for security and governance violations before deployment. When HIGH severity violations are found, the pipeline fails and the PR is blocked from merging. All findings are logged to Azure Table Storage for audit."

### Architecture Explanation (2 minutes)
"The system has four main components. First, Terraform defines the infrastructure — both the backend storage for state and violation logs, and the demo infrastructure that we scan. Second, the Azure DevOps pipeline triggers on PRs and has two stages: Terraform Plan and Policy Check. Third, the Python policy engine parses the plan JSON and runs 5 rules against every resource. Fourth, the reporter posts results as PR comments and logs them to Table Storage."

### Technical Deep Dive (3 minutes)
"The engine uses the Strategy pattern — each rule implements a common `evaluate()` interface. This makes it trivial to add new rules. The plan JSON is parsed from `planned_values.root_module.resources`, extracting the address, type, and values for each resource. The 5 rules check for public storage accounts, missing tags, SSH open to the internet, naming convention violations, and unencrypted disks. HIGH severity violations cause exit code 1, which fails the pipeline."

### Demo Explanation (2 minutes)
"The demo infrastructure is intentionally non-compliant. It has a storage account with public access, resources missing required tags, an NSG rule allowing SSH from 0.0.0.0/0, resources with uppercase names, and a managed disk without encryption. When the pipeline runs, it detects 14 violations across these resources and fails — which is the correct behavior. This validates that the policy gate works."

### Closing / Extensions (1 minute)
"The system is designed for extensibility. Adding a new rule is a one-file change. Future enhancements could include a YAML config for rule thresholds, an exemption system, Teams/Slack notifications, Infracost integration for cost estimation, or a Power BI dashboard on top of Table Storage for compliance trend reporting."

---

## 12. Debugging & Troubleshooting Journey

This project required resolving multiple real-world infrastructure, authentication, Terraform, Git, and Azure DevOps integration issues during implementation. The debugging process itself became a significant learning component of the project.

---

### 1. Azure CLI Authentication & Tenant Resolution

Initial Azure CLI logins authenticated against the wrong tenant and subscription, causing commands such as:

```bash
az account set --subscription <subscription-id>
```

to fail with:

```text
The subscription doesn't exist in cloud 'AzureCloud'
```

#### Root Cause

* Azure CLI cached credentials from a different tenant
* MFA enforcement interrupted tenant enumeration
* Subscription was not loaded into the active CLI context

#### Resolution

* Cleared Azure CLI cache:

  ```bash
  az logout
  az account clear
  ```
* Re-authenticated using:

  ```bash
  az login --use-device-code
  ```
* Explicitly selected the correct subscription:

  ```bash
  az account set --subscription <new-subscription-id>
  ```

---

### 2. Frozen Azure Subscription / Deny Assignment

The original Azure subscription appeared healthy in the portal but failed all write operations.

Commands such as:

```bash
az group create --name rg-test-policygate --location centralindia
```

failed with:

```text
DenyAssignmentAuthorizationFailed
Subscription frozen due to inactivity for an year or more
```

#### Root Cause

The subscription had a subscription-level deny assignment enforced by Azure due to inactivity.

#### Impact

The deny assignment blocked:

* Resource Group creation
* RBAC changes
* Service Principal creation
* Terraform deployments

even though the account had `Owner` RBAC permissions.

#### Resolution

* Created a brand-new Pay-As-You-Go Azure subscription
* Reconfigured Azure CLI authentication
* Verified write capability using:

  ```bash
  az group create
  ```

---

### 3. Terraform Backend Deployment

The backend Terraform module successfully provisioned:

* Azure Resource Group
* Storage Account
* Blob Container
* Table Storage

#### Issue Encountered

Terraform storage account naming initially conflicted with Azure naming restrictions.

Azure requires:

* lowercase only
* alphanumeric only
* 3–24 characters

#### Resolution

Renamed invalid storage account names to compliant lowercase variants.

---

### 4. Terraform Plan Generation Failure

Initial Terraform plan generation failed before policy evaluation due to invalid Azure resource names.

Example failure:

```text
name ("DEMOPUBLICSTORAGE123") can only consist of lowercase letters and numbers
```

#### Root Cause

The intentionally non-compliant demo infrastructure violated Azure syntax rules before policy validation could execute.

#### Resolution

Modified demo resource names to:

* remain policy-noncompliant
* but become Azure-valid syntactically

Example:

```hcl
name = "demopublicstorage123"
```

---

### 5. Local Policy Engine Validation

The Terraform plan was converted into JSON:

```bash
terraform show -json tfplan.bin > tfplan.json
```

The Python policy engine successfully detected:

* PUBLIC_STORAGE violations
* NSG_SSH_OPEN violations
* REQUIRED_TAGS violations
* NAMING_CONVENTION violations
* DISK_ENCRYPTION violations

Result:

```text
[FAIL] HIGH severity violations detected -- pipeline FAILED.
```

This intentional failure validated the governance enforcement logic.

---

### 6. Git & Repository Hygiene Issues

Generated artifacts were accidentally committed:

* `tfplan.bin`
* `policy-report.md`

#### Resolution

* Removed generated files from Git tracking:

  ```bash
  git rm --cached
  ```
* Added exclusions to `.gitignore`

Example:

```gitignore
terraform/demo/tfplan.bin
terraform/demo/tfplan.json
policy-report.md
.terraform/
*.tfstate
```

---

### 7. Git Push / Branch Issues

Git push initially failed due to:

* incorrect branch (`main` vs `master`)
* remote history divergence

#### Resolution

Used:

```bash
git pull --rebase origin master
git push origin master
```

---

### 8. Azure DevOps Service Connection Issues

Automatic Azure DevOps service connection creation failed with:

```text
AADSTS70025:
no configured federated identity credentials
```

#### Root Cause

Workload Identity Federation was selected without configuring federated credentials in Microsoft Entra ID.

#### Resolution

Switched to:

* Manual App Registration
* Service Principal Key authentication

Used:

```bash
az ad sp create-for-rbac
```

and manually configured:

* Tenant ID
* Client ID
* Client Secret
* Subscription ID

inside Azure DevOps.

---

### 9. Azure Pipelines YAML Parsing Errors

Pipeline creation initially failed with YAML syntax errors:

```text
did not find expected '-' indicator
```

#### Root Cause

Mixed YAML mapping and list syntax inside the `variables:` block.

#### Resolution

Rewrote variables section using proper list syntax:

```yaml
variables:
  - group: policy-gate-vars

  - name: TF_WORKING_DIR
    value: "terraform/demo"
```

---

### 10. Missing TerraformInstaller Task

Azure DevOps pipeline failed because:

```text
TerraformInstaller@1
```

was unavailable.

#### Root Cause

The Microsoft DevLabs Terraform extension was not installed in Azure DevOps.

#### Resolution

Installed:

* Terraform extension from Azure DevOps Marketplace

Alternative shell-based installation was also evaluated for portability.

---

### 11. Final Pipeline Validation

The Azure DevOps pipeline ultimately executed:

1. Terraform initialization
2. Terraform planning
3. Terraform JSON export
4. Python policy engine execution
5. Violation reporting
6. Pipeline failure on HIGH severity findings

The intentional pipeline failure confirmed:

* policy-as-code enforcement
* governance validation
* CI/CD security gate functionality
* PR blocking behavior

The final system successfully demonstrated automated infrastructure compliance enforcement using Terraform, Python, Azure Storage, and Azure DevOps.
