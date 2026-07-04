# Design Spec — Policy-as-Code Configuration (policy.yml)

Implement a centralized YAML configuration loader to allow teams to enable/disable rules, override rule severities, and customize rule-specific parameters (e.g. required tags or naming convention prefixes).

## Requirements & Scope

1. **YAML File (`policy.yml`)**:
   - Location: root of the workspace.
   - Format: dictionary keyed by rule ID.
   - Fallback: cleanly defaults to current hardcoded values if `policy.yml` is missing.
   - Loud Failure: raises a clear, descriptive error on malformed YAML or schema validation failure.
   - Strict Parameter Validation: Only explicitly supported parameters (e.g. `tags` for `REQUIRED_TAGS`, `prefixes` for `NAMING_CONVENTION`) are allowed; unknown parameters must fail loudly with a `PolicyConfigError`.

2. **Decoupled Architecture**:
   - Rules implementation remains focused entirely on evaluation logic and has no knowledge of YAML files.
   - Abstract `PolicyRule` interface is unchanged.
   - Configuration is loaded and validated exactly once at startup.
   - Parameter overrides are applied prior to evaluation.
   - Severity overrides are applied post-evaluation by the orchestrator.

3. **Schema Definition**:
   ```yaml
   rules:
     REQUIRED_TAGS:
       enabled: true
       severity: HIGH
       parameters:
         tags: ["owner", "env", "project", "cost-centre"]
     NAMING_CONVENTION:
       enabled: true
       severity: MEDIUM
       parameters:
         prefixes:
           azurerm_resource_group: "rg-"
   ```

## Proposed Architecture

A new config module `policy_engine/config.py` will be created to handle YAML parsing and schema validation.

```
policy.yml
      ↓
policy_engine/config.py (load_policy_config)
      ↓
policy_engine/engine.py (evaluate_plan)
      ↓
Rules parameter overrides (set attributes)
      ↓
Evaluate (rule.evaluate)
      ↓
Severity overrides (update Violation.severity)
      ↓
aggregated PolicyResult
```

### Changes in `policy_engine/rules/required_tags.py`
- Modify `evaluate` to use `getattr(self, "required_tags", REQUIRED_TAGS)` instead of directly referencing the global `REQUIRED_TAGS` set.

### Changes in `policy_engine/rules/naming_convention.py`
- Modify `evaluate` to use `getattr(self, "naming_patterns", NAMING_PATTERNS)` instead of directly referencing the global `NAMING_PATTERNS` dictionary.

### New Module `policy_engine/config.py`
- Exposes `PolicyConfigError`.
- Exposes `load_policy_config(config_path: Path | str | None) -> dict[str, Any] | None`.
- Exposes `apply_config_to_rules(rules: list[PolicyRule], config: dict[str, Any] | None) -> list[PolicyRule]`.
- Exposes `apply_severity_override(violations: list[Violation], rule_id: str, config: dict[str, Any] | None) -> None`.

## Verification & Testing Plan

- **Missing Config Test**: Verify that the engine behaves exactly as before when `policy.yml` is missing.
- **Enabled/Disabled Test**: Verify that rules set to `enabled: false` are filtered out and not executed.
- **Severity Override Test**: Verify that a rule's severity is updated to the overridden value (e.g. `REQUIRED_TAGS` overridden from `HIGH` to `MEDIUM`).
- **Parameter Override Test**:
  - Custom tag list for `REQUIRED_TAGS`.
  - Custom prefixes list for `NAMING_CONVENTION`.
- **Loud Failure Test**: Verify that malformed YAML or invalid schema (e.g. invalid severity level like `CRITICAL`) raises a descriptive `PolicyConfigError`.
