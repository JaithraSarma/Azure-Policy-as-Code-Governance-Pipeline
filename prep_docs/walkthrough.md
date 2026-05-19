# Azure Policy Gate — Implementation Walkthrough

## What Was Built

A complete **Terraform compliance engine** that integrates with Azure DevOps Pipelines to gate pull requests based on policy violations. The project is fully self-contained — Azure DevOps + Terraform + Python only. No external tools, no third-party services.

---

## Components Built

### 1. Terraform Backend Infrastructure (`terraform/backend/`)
- **Resource Group** (`rg-policy-gate-backend`) — container for all backend resources
- **Storage Account** — hosts both blob storage for Terraform remote state and Table Storage for violation audit logs
- **Blob Container** (`tfstate`) — Terraform remote state backend
- **Storage Table** (`PolicyViolations`) — structured audit log for every violation detected

### 2. Demo Infrastructure (`terraform/demo/`)
Intentionally non-compliant Terraform configuration that triggers all 5 policy rules:
- Storage Account with public network access enabled
- Resources missing required tags (`owner`, `env`, `project`, `cost-centre`)
- NSG rule allowing SSH (port 22) from `0.0.0.0/0`
- Resources with naming convention violations (uppercase, missing prefixes)
- Managed disk without encryption configured

### 3. Python Policy Engine (`policy_engine/`)
Modular, extensible rule engine with:
- **Abstract base class** (`PolicyRule`) for all rules
- **5 concrete rules** — each in its own module
- **Engine orchestrator** — parses Terraform plan JSON, runs all rules
- **Reporter** — formats markdown PR comments, posts via Azure DevOps REST API, logs to Table Storage
- **CLI entry point** — exit code 0 (pass) or 1 (fail based on HIGH severity)

### 4. Azure DevOps Pipeline (`azure-pipelines.yml`)
Two-stage pipeline:
- **Stage 1: Terraform Plan** — init, plan, convert to JSON, publish artifact
- **Stage 2: Policy Check** — download artifact, run Python engine, post results

### 5. Test Suite (`tests/`)
- 34 unit and integration tests
- Covers all 5 rules individually + engine integration + reporter formatting
- Two plan fixtures: non-compliant (14 violations) and compliant (0 violations)

---

## Policy Rules Summary

| # | Rule ID | Severity | What It Catches |
|---|---------|----------|----------------|
| 1 | `PUBLIC_STORAGE` | HIGH | Public storage accounts (public_network_access, nested public, network rules Allow) |
| 2 | `REQUIRED_TAGS` | HIGH | Missing mandatory tags: owner, env, project, cost-centre |
| 3 | `NSG_SSH_OPEN` | HIGH | NSG rules allowing SSH (port 22) from 0.0.0.0/0 or * |
| 4 | `NAMING_CONVENTION` | MEDIUM | Names violating Cloud Adoption Framework patterns |
| 5 | `DISK_ENCRYPTION` | HIGH | Managed disks without encryption configured |

---

## Verification Results

### Unit Tests — 34/34 PASSED
```
======================== 34 passed in 0.38s ========================
```

### Engine E2E — Non-Compliant Plan → 14 violations, exit code 1
```
Scanned 6 resources — 14 violation(s) (HIGH: 10, MEDIUM: 4)
[FAIL] HIGH severity violations detected -- pipeline FAILED.
```

### Engine E2E — Compliant Plan → 0 violations, exit code 0
```
Scanned 4 resources — 0 violation(s) (HIGH: 0, MEDIUM: 0)
[PASS] All checks passed.
```

---

## Key Design Decisions

1. **Shell-based Terraform install** — avoids marketplace extension dependency, more portable
2. **Variable group** (`policy-gate-vars`) — centralizes secrets management in Azure DevOps Library
3. **Manual Service Principal** — simpler than Workload Identity Federation, works out of the box
4. **Abstract base class pattern** — makes adding new rules a one-file change
5. **Dual extraction strategy** — engine handles both `planned_values` and `resource_changes` JSON formats
6. **ASCII-safe CLI output** — `_safe_print()` with UTF-8 wrapping prevents encoding crashes on Windows
