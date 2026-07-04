# Design Spec — Exemptions System (exemptions.yml)

Implement a post-evaluation exemptions system using a separate `exemptions.yml` file to allow teams to accept risk on specific resource-rule violations with a documented reason.

## Requirements & Scope

1. **Exemptions File (`exemptions.yml`)**:
   - Location: root of the workspace.
   - Format: dictionary mapping `resource_address` -> `rule_id` -> `reason` (supports both a direct string reason, or a dictionary containing a `reason` key, normalized internally to `dict[str, dict[str, Any]]` for future extensibility).
   - Validation:
     - Reject missing reasons or empty strings.
     - Reject unknown rule IDs (must match one of the registered rule IDs).
     - Reject malformed structures.
     - Reject unknown resource addresses (validated during applying exemptions against the resources in the plan).

2. **Decoupled Architecture**:
   - Loaded and validated in a dedicated module `policy_engine/exemptions.py`.
   - Applied after rule evaluation finishes.
   - Exempted violations are excluded from the pipeline failure condition (`has_high_severity` will ignore them).
   - Exempted violations are still reported in the markdown comment and logged to Table Storage with `Exempted=True` and the `ExemptionReason`.

## Proposed Architecture

```
exemptions.yml
      ↓
policy_engine/exemptions.py (load_exemptions)
      ↓
policy_engine/engine.py (evaluate_plan)
      ↓
Rule evaluation
      ↓
Apply exemptions & validate resource addresses exist (apply_exemptions)
      ↓
aggregated PolicyResult
```

### Changes in `policy_engine/models.py`
- Add `exempted: bool = False` to `Violation`.
- Add `exemption_reason: str | None = None` to `Violation`.
- Update `Violation.to_dict()` to serialize `exempted` and `exemption_reason` (suitable for Azure Table Storage).
- Update `PolicyResult.has_high_severity` property:
  ```python
  @property
  def has_high_severity(self) -> bool:
      return any(v.severity == Severity.HIGH and not v.exempted for v in self.violations)
  ```

### New Module `policy_engine/exemptions.py`
- Exposes `ExemptionConfigError`.
- Exposes `load_exemptions(config_path: Path | str | None) -> dict[str, dict[str, Any]]`.
- Exposes `apply_exemptions(violations: list[Violation], exemptions: dict[str, dict[str, Any]], plan_resources: list[str]) -> None`.

### Reporter Updates (`policy_engine/reporter.py`)
- Update PR markdown formatter to display exempted violations in a separate table/section labeled "Exempted Violations" rather than treating them as blocking errors.

## Verification & Testing Plan

- **Valid Exemption**: Verify that an exempted violation does not fail the pipeline.
- **Bare Suppression**: Verify that an exemption with a missing or empty reason raises `ExemptionConfigError`.
- **Unknown Rule ID**: Verify that an exemption containing an unknown rule ID raises `ExemptionConfigError`.
- **Unknown Resource Address**: Verify that an exemption for a resource address not present in the evaluated plan raises `ExemptionConfigError`.
- **Targeted Suppression**: Verify that an exemption for `PUBLIC_STORAGE` on `azurerm_storage_account.demo` does not suppress `REQUIRED_TAGS` violations on that same storage account.
