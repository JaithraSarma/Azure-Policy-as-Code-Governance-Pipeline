# Azure Policy Gate — Quick Reference Card

Use this as a rapid-fire study sheet before interviews or vivas.

---

## One-Line Description
> A Python policy engine integrated with Azure DevOps Pipelines that scans Terraform plans for compliance violations, blocks non-compliant PRs, and logs findings to Azure Table Storage.

---

## Tech Stack (memorize this)
| Layer | Technology |
|-------|-----------|
| CI/CD | Azure DevOps Pipelines (YAML) |
| IaC | Terraform (AzureRM provider) |
| Policy Engine | Python 3.11 |
| State Storage | Azure Blob Storage |
| Audit Log | Azure Table Storage |
| PR Integration | Azure DevOps REST API v7.1 |
| Auth | Service Principal (Client Secret) |

---

## 5 Policy Rules (memorize these)

| Rule | Severity | One-Line |
|------|----------|----------|
| PUBLIC_STORAGE | HIGH | Detects storage accounts with public network access |
| REQUIRED_TAGS | HIGH | Enforces owner, env, project, cost-centre tags |
| NSG_SSH_OPEN | HIGH | Blocks SSH port 22 open to 0.0.0.0/0 |
| NAMING_CONVENTION | MEDIUM | Validates Cloud Adoption Framework naming (rg-, st, vnet-, etc.) |
| DISK_ENCRYPTION | HIGH | Requires encryption on managed disks |

---

## Pipeline Flow (draw this)
```
PR → Pipeline Trigger → terraform plan → JSON → Python Engine → PR Comment + Table Log
                                                     │
                                                     ├── exit 0 → PASS → merge allowed
                                                     └── exit 1 → FAIL → PR blocked
```

---

## Key Files to Know
| File | What It Does |
|------|-------------|
| `azure-pipelines.yml` | 2-stage pipeline definition |
| `policy_engine/engine.py` | Parses plan JSON, runs all rules |
| `policy_engine/rules/base.py` | Abstract PolicyRule class |
| `policy_engine/reporter.py` | PR comment + Table Storage writer |
| `policy_engine/main.py` | CLI entry point, exit code logic |
| `terraform/backend/main.tf` | Backend storage (state + table) |
| `terraform/demo/main.tf` | Intentionally non-compliant infra |

---

## Critical Commands
```bash
# Run tests
python -m pytest tests/ -v

# Run engine locally
python -m policy_engine.main tests/fixtures/demo_plan.json

# Generate terraform plan JSON
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > tfplan.json

# Create service principal
az ad sp create-for-rbac --name "sp-policy-gate-pipeline" --role Contributor --scopes /subscriptions/<SUB_ID>
```

---

## Common Interview Questions & Answers

**Q: Why does the pipeline fail?**
A: By design. The demo infrastructure is intentionally non-compliant to prove the policy gate works.

**Q: Why Python and not OPA/Sentinel?**
A: Project constraint — no external tools. Python gives full control, is Azure-native via SDK, and is more accessible.

**Q: How do you add a new rule?**
A: Create a new file in `policy_engine/rules/`, subclass `PolicyRule`, implement `evaluate()`, register in `__init__.py`.

**Q: Why Table Storage and not SQL/Cosmos?**
A: Cheapest option for structured audit logging. Partitioned by PR number, queryable, no schema management needed.

**Q: What happens to MEDIUM violations?**
A: They appear in the PR comment as warnings but do NOT fail the pipeline or block the merge.

**Q: How is Terraform installed in the pipeline?**
A: Shell-based `curl` download — no marketplace extension dependency, more portable.
