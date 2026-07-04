# Setup & Debugging Guide

This manual covers the steps to run the Azure Policy Gate locally and in CI/CD, along with a collection of troubleshooting guides and root causes compiled from real development scenarios.

---

## Local Execution Guide

### 1. Installation

Install all required Python dependencies:
```bash
python -m pip install -r requirements.txt
```

### 2. Generate a Terraform Plan JSON
To evaluate policies, you must first output a standard Terraform plan binary and convert it to JSON format.

> [!CAUTION]
> **PowerShell Redirect Encoding Issue**:
> Avoid running `terraform show -json tfplan.bin > tfplan.json` in PowerShell. On Windows environments, PowerShell's default redirect operator (`>`) encodes files in UTF-16 (with a Byte Order Mark). This will cause Python's JSON loader to throw a `UnicodeDecodeError`.
>
> **The Fix**:
> Run the conversion command using Python to output a clean UTF-8 encoded file:
> ```powershell
> python -c "import subprocess; out = subprocess.check_output(['terraform', 'show', '-json', 'tfplan.bin']); open('tfplan.json', 'wb').write(out)"
> ```

### 3. Run the Policy Engine
Run the main script against your plan JSON:

```bash
# Default markdown report output
python -m policy_engine.main terraform/demo/tfplan.json

# Export an additional SARIF report
python -m policy_engine.main terraform/demo/tfplan.json --format sarif
```

> [!TIP]
> **ModuleNotFoundError (policy_engine)**:
> If running the engine from inside a subdirectory (e.g. `terraform/demo/`), Python will fail to locate the package. Navigate back to the repository root directory before executing, or set `PYTHONPATH` explicitly:
> - PowerShell: `$env:PYTHONPATH="..\.."`
> - Bash: `export PYTHONPATH="../.."`

---

## Pipeline Configuration

### 1. OIDC / Workload Identity Federation (WIF)
Always prefer Workload Identity Federation (OIDC) via `azure-policy-gate-sc` instead of hardcoding service principal client secrets. WIF is configured dynamically within `azure-pipelines.yml` inside `AzureCLI@2` tasks.

### 2. Detailed Exit Codes
When executing plans in CI, use `terraform plan -detailed-exitcode`. This exit code must be handled properly so that a non-empty plan (exit code `2`) does not fail the build, but real plan failures (exit code `1`) are caught:
```bash
terraform plan -out=tfplan.bin -input=false -detailed-exitcode
PLAN_EXIT_CODE=$?
if [ $PLAN_EXIT_CODE -eq 1 ]; then
  exit 1
elif [ $PLAN_EXIT_CODE -eq 0 ] || [ $PLAN_EXIT_CODE -eq 2 ]; then
  exit 0
fi
```

---

## Debugging & Common Root Causes

### 1. Terraform Schema Validation Errors
- **Symptom**: `terraform plan` fails during validation (e.g. parsing `fake-server-id` throws invalid URI errors).
- **Root Cause**: Terraform validates IDs of dependent resources (such as server IDs and App Service plans) *before* evaluating policies. Using simple placeholder strings like `fake-id` breaks validation.
- **Solution**: Declare minimal real dependent resources in your demo (`azurerm_mssql_server` and `azurerm_service_plan`) and reference their generated IDs (e.g. `azurerm_mssql_server.demo.id`).

### 2. GitHub Push Secret Scanning Rejections
- **Symptom**: Push rejected by remote with `Repository rule violations: Push cannot contain secrets`.
- **Root Cause**: Unsanitized plan JSON files (`tfplan.json`) generated from active cloud configurations contain real access keys and connection strings.
- **Solution**: Replace any base64 access keys of length 80-95 inside the plan file with dummy redacted strings before committing:
  ```python
  import re
  content = re.sub(r'[A-Za-z0-9+/=]{80,95}', 'REDACTED_ACCESS_KEY_GOES_HERE', content)
  ```
