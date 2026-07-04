# Setup Guide

This guide covers setting up, running, and integrating the **Azure Policy Gate** compliance engine.

---

## 1. Local Setup

### Prerequisites
- **Python 3.11+**
- **Terraform 1.5+**
- **Azure CLI**

### Installation
Clone the repository and install the dependencies:
```bash
python -m pip install -r requirements.txt
```

### Run Unit Tests
To verify your installation and check that all 61 tests are passing:
```bash
python -m pytest tests/ -v
```

---

## 2. Local Execution

To run compliance checks locally, you must generate a Terraform plan in JSON format.

### Step 1: Initialize and Plan
```bash
cd terraform/demo
terraform init
terraform plan -out=tfplan.bin
```

### Step 2: Convert to JSON
Convert the binary plan to JSON using Python to ensure UTF-8 encoding (avoiding PowerShell redirection encoding issues):
```powershell
python -c "import subprocess; out = subprocess.check_output(['terraform', 'show', '-json', 'tfplan.bin']); open('tfplan.json', 'wb').write(out)"
```

### Step 3: Run the Policy Gate
Run the policy engine against the generated JSON plan from the repository root:
```bash
# Return to the root directory
cd ../..

# Run engine (Outputs Markdown report to policy-report.md)
python -m policy_engine.main terraform/demo/tfplan.json

# Run engine and export a SARIF report as well
python -m policy_engine.main terraform/demo/tfplan.json --format sarif
```

---

## 3. Pipeline Setup (Azure DevOps)

The project includes an `azure-pipelines.yml` pipeline that triggers on pull requests modifying files in the `terraform/` folder.

### Step 1: Azure Service Connection (OIDC / WIF)
Configure a Service Connection named `azure-policy-gate-sc` in Azure DevOps using **Workload Identity Federation (OIDC)**. This enables secure connection without needing persistent client secrets.

### Step 2: Pipeline Variables
Define the following environment variables in your Azure DevOps pipeline configuration:
- `AZURE_STORAGE_CONNECTION_STRING`: Connection string for the Azure Table Storage account where compliance violations will be logged.
- `VIOLATIONS_TABLE_NAME`: Name of the storage table (defaults to `PolicyViolations` if not specified).

### Step 3: Run PR Pipeline
Create a pipeline using the existing `azure-pipelines.yml` file. When a PR is created, the pipeline will evaluate your plan, write results to the audit storage table, and post violation details back to the PR as an inline comment.

---

## 4. Troubleshooting

### `ModuleNotFoundError: No module named 'policy_engine'`
- **Reason**: You are running the python execution from within a subdirectory.
- **Fix**: Run the command from the repository root directory, or set your `PYTHONPATH` environment variable:
  - PowerShell: `$env:PYTHONPATH="..\.."`
  - Bash: `export PYTHONPATH="../.."`

### `UnicodeDecodeError` when loading plan JSON
- **Reason**: Generating the JSON file via PowerShell's redirection (`>`) operator encodes it in UTF-16.
- **Fix**: Use the Python conversion command described in Section 2 to write a standard UTF-8 encoded JSON file.
