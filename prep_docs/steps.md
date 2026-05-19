# Azure Policy Gate — Implementation Steps

A chronological record of how this project was built, from scratch to fully working pipeline.

---

## Phase 1: Project Scaffold

1. Created `.gitignore` with Python + Terraform exclusions
2. Created `requirements.txt` with `azure-data-tables`, `requests`, `pytest`

---

## Phase 2: Terraform Backend Infrastructure

3. Created `terraform/backend/main.tf` — Resource Group, Storage Account (blob + table)
4. Created `terraform/backend/variables.tf` — parameterized naming with validation
5. Created `terraform/backend/outputs.tf` — connection info for downstream use
6. Deployed backend: `terraform init && terraform apply`
7. Retrieved storage connection string via `az storage account show-connection-string`

---

## Phase 3: Demo Infrastructure (Intentionally Non-Compliant)

8. Created `terraform/demo/providers.tf` — AzureRM provider config
9. Created `terraform/demo/backend.tf` — remote state pointing to backend storage
10. Created `terraform/demo/main.tf` — 6 resources with intentional violations:
    - Resource Group with missing tags and bad naming
    - Storage Account with public access enabled
    - NSG with SSH open to 0.0.0.0/0
    - Managed Disk without encryption
    - Virtual Network with no tags and bad naming
11. Created `terraform/demo/variables.tf` and `outputs.tf`

---

## Phase 4: Policy Engine Foundation

12. Created `policy_engine/__init__.py` — package initialization
13. Created `policy_engine/models.py` — `Violation`, `PolicyResult`, `Severity` data classes
14. Created `policy_engine/rules/base.py` — abstract `PolicyRule` base class

---

## Phase 5: Policy Rules (one per file)

15. Created `policy_engine/rules/public_storage.py` — PUBLIC_STORAGE rule (3 checks)
16. Created `policy_engine/rules/required_tags.py` — REQUIRED_TAGS rule
17. Created `policy_engine/rules/nsg_ssh_open.py` — NSG_SSH_OPEN rule (standalone + inline)
18. Created `policy_engine/rules/naming_convention.py` — NAMING_CONVENTION rule (10 resource types)
19. Created `policy_engine/rules/disk_encryption.py` — DISK_ENCRYPTION rule
20. Created `policy_engine/rules/__init__.py` — registered all 5 rules in ALL_RULES

---

## Phase 6: Engine Core & Reporting

21. Created `policy_engine/engine.py` — plan JSON parser + rule orchestrator
22. Created `policy_engine/reporter.py` — markdown formatter + Azure DevOps PR comment + Table Storage logger
23. Created `policy_engine/main.py` — CLI entry point with exit code gating

---

## Phase 7: Testing

24. Created `tests/fixtures/demo_plan.json` — non-compliant plan fixture
25. Created `tests/fixtures/compliant_plan.json` — fully compliant plan fixture
26. Created `tests/test_rules.py` — 34 unit + integration tests
27. Ran tests: `python -m pytest tests/ -v` → 34/34 PASSED

---

## Phase 8: Azure DevOps Pipeline

28. Created `azure-pipelines.yml` with 2 stages:
    - Stage 1: Terraform Plan (shell-based install, init, plan, JSON export)
    - Stage 2: Policy Check (Python engine, PR comment, Table Storage, exit code)
29. Used variable group `policy-gate-vars` for secrets
30. Used shell-based Terraform install (no marketplace dependency)

---

## Phase 9: Azure DevOps Configuration

31. Created Service Principal: `az ad sp create-for-rbac`
32. Created manual Service Connection in Azure DevOps (SP key auth)
33. Created variable group `policy-gate-vars` with ARM_* and connection string
34. Created pipeline from existing YAML
35. Configured branch protection with Build Validation policy

---

## Phase 10: Documentation & Finalization

36. Created `docs/SETUP_GUIDE.md` — step-by-step Azure DevOps configuration
37. Created `README.md` — comprehensive project documentation
38. Created `LICENSE` — MIT
39. Pushed to GitHub with 27 meaningful commits
40. Created prep_docs/ with theory, walkthrough, and steps

---

## Issues Encountered & Resolved

| Issue | Resolution |
|-------|-----------|
| Unicode encoding on Windows console | Added `_safe_print()` with UTF-8 wrapping |
| Demo storage name violated Azure syntax | Changed to lowercase (remain policy-noncompliant but Azure-valid) |
| Workload Identity Federation failed | Switched to manual SP key authentication |
| TerraformInstaller@1 requires marketplace | Switched to shell-based curl install |
| YAML variables syntax errors | Rewrote using proper list syntax with `- name: / value:` |
