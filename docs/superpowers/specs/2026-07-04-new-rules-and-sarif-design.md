# Design Spec — New Rules & SARIF Output (Phase 3 & 4)

Implement two new high-value rules (`SQL_FIREWALL_OPEN` and `HTTPS_ONLY`) and add an option to generate a SARIF 2.1.0 report alongside the default markdown report.

## Requirements & Scope

1. **SQL_FIREWALL_OPEN Rule**:
   - ID: `SQL_FIREWALL_OPEN`
   - Severity: `HIGH`
   - Target resources: `azurerm_sql_firewall_rule`, `azurerm_mssql_firewall_rule`.
   - Violation criteria: `start_ip_address == "0.0.0.0"` (covers both internal Azure services access and full internet access), `start_ip_address == "*"`, `end_ip_address == "*"`, or `end_ip_address == "255.255.255.255"`.

2. **HTTPS_ONLY Rule**:
   - ID: `HTTPS_ONLY`
   - Severity: `HIGH`
   - Target resources: `azurerm_app_service`, `azurerm_linux_web_app`, `azurerm_windows_web_app`, `azurerm_function_app`.
   - Violation criteria: `https_only` attribute is not `True` (e.g. `False`, `None` or missing).

3. **SARIF Output**:
   - Emits findings in SARIF 2.1.0 format alongside the markdown report.
   - Command line flag: `--format sarif` trigger.
   - Output path: defaults to `policy-report.sarif`, customizable via `POLICY_SARIF_PATH` environment variable.
   - Decoupled formatter class in `policy_engine/sarif.py`.

## Proposed Architecture

### Rule Implementations
- Create [sql_firewall_open.py](file:///c:/Users/Jaith/Desktop/projects/Azure%20policy%20gate/policy_engine/rules/sql_firewall_open.py) inheriting `PolicyRule`.
- Create [https_only.py](file:///c:/Users/Jaith/Desktop/projects/Azure%20policy%20gate/policy_engine/rules/https_only.py) inheriting `PolicyRule`.
- Register both rules in [rules/\_\_init\_\_.py](file:///c:/Users/Jaith/Desktop/projects/Azure%20policy%20gate/policy_engine/rules/__init__.py).

### SARIF Generation
- Create [sarif.py](file:///c:/Users/Jaith/Desktop/projects/Azure%20policy%20gate/policy_engine/sarif.py) to build valid SARIF JSON objects.
- Severity mapping:
  - `HIGH` -> `error`
  - `MEDIUM` -> `warning`
  - `LOW` -> `note`
- Logical resource locations mapped to resource addresses.

### Entrypoint Updates
- Update [main.py](file:///c:/Users/Jaith/Desktop/projects/Azure%20policy%20gate/policy_engine/main.py) to use `argparse` for CLI arguments parsing.
- Default to markdown format. If `--format sarif` is specified, generate and write the SARIF report to the determined path.

## Verification & Testing Plan

- **SQL_FIREWALL_OPEN Tests**:
  - `start_ip_address = "0.0.0.0"` and `end_ip_address = "0.0.0.0"` flags a violation.
  - `start_ip_address = "0.0.0.0"` and `end_ip_address = "255.255.255.255"` flags a violation.
  - Restricted IP ranges (e.g., `10.0.0.0` - `10.0.0.255`) pass.
- **HTTPS_ONLY Tests**:
  - `https_only = false` or missing flags a violation.
  - `https_only = true` passes.
- **SARIF Tests**:
  - Verify valid SARIF v2.1.0 output schema.
  - Verify severity mapping matches `error`, `warning`, `note`.
- **Pipeline integration**:
  - Update `terraform/demo/main.tf` to include one intentionally non-compliant resource for each new rule.
