# Detailed Setup & Configuration Guide

This guide walks you through every step needed to connect Azure DevOps to your Azure subscription and configure the pipeline to protect your branches.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Create the Service Principal](#2-create-the-service-principal)
3. [Deploy Backend Infrastructure](#3-deploy-backend-infrastructure)
4. [Set Up Azure DevOps Project](#4-set-up-azure-devops-project)
5. [Create the Service Connection](#5-create-the-service-connection)
6. [Configure Pipeline Variables](#6-configure-pipeline-variables)
7. [Create the Pipeline](#7-create-the-pipeline)
8. [Configure Branch Protection](#8-configure-branch-protection)
9. [Test the Setup](#9-test-the-setup)

---

## 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Azure Subscription** | Any tier (Free, Pay-As-You-Go, Enterprise) |
| **Azure CLI** | v2.50+ — [Install](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| **Terraform CLI** | v1.5+ — [Install](https://developer.hashicorp.com/terraform/install) |
| **Python** | 3.10+ — [Install](https://www.python.org/downloads/) |
| **Azure DevOps Organisation** | [Create free](https://dev.azure.com/) |
| **Git** | Any recent version |

---

## 2. Create the Service Principal

The pipeline needs an identity to authenticate with Azure. Create a Service Principal with `Contributor` role:

```bash
# Login to Azure
az login

# Set your subscription
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"

# Create a Service Principal
az ad sp create-for-rbac \
  --name "sp-policy-gate-pipeline" \
  --role Contributor \
  --scopes /subscriptions/<YOUR_SUBSCRIPTION_ID> \
  --sdk-auth
```

**Save the output** — you will need these values:

```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

---

## 3. Deploy Backend Infrastructure

The backend provisions the Storage Account for Terraform state and the Table Storage table for violation logs.

```bash
cd terraform/backend

# Initialise (local state for the backend itself)
terraform init

# Review the plan
terraform plan -var="storage_account_name=stpolicygatestate" \
               -var="owner=your-name" \
               -var="cost_centre=CC-001"

# Apply
terraform apply -auto-approve \
  -var="storage_account_name=stpolicygatestate" \
  -var="owner=your-name" \
  -var="cost_centre=CC-001"
```

> **Important:** The `storage_account_name` must be globally unique across all of Azure. If `stpolicygatestate` is taken, choose a different name and update `terraform/demo/backend.tf` accordingly.

### Get the Storage Connection String

```bash
az storage account show-connection-string \
  --name stpolicygatestate \
  --resource-group rg-policy-gate-backend \
  --query connectionString -o tsv
```

Save this — you will need it for the pipeline variable `AZURE_STORAGE_CONNECTION_STRING`.

---

## 4. Set Up Azure DevOps Project

1. Go to [dev.azure.com](https://dev.azure.com)
2. Create a new **Project** (e.g., `azure-policy-gate`)
3. Under **Repos**, import or push this repository:

```bash
cd /path/to/azure-policy-gate
git init
git remote add origin https://dev.azure.com/<ORG>/<PROJECT>/_git/azure-policy-gate
git add -A
git commit -m "Initial commit — azure-policy-gate"
git push -u origin main
```

---

## 5. Create the Service Connection

This allows the pipeline to authenticate with Azure:

1. In Azure DevOps, go to **Project Settings** → **Service connections**
2. Click **New service connection** → **Azure Resource Manager**
3. Select **Service principal (manual)**
4. Fill in the details from Step 2:

| Field | Value |
|-------|-------|
| Subscription ID | `<subscriptionId>` from SP output |
| Subscription Name | Your subscription name |
| Service Principal ID | `<clientId>` from SP output |
| Service Principal Key | `<clientSecret>` from SP output |
| Tenant ID | `<tenantId>` from SP output |
| Service Connection Name | `azure-policy-gate-sc` |

5. Check **Grant access permission to all pipelines**
6. Click **Verify and save**

---

## 6. Configure Pipeline Variables

The pipeline needs several secret variables. Configure them in Azure DevOps:

1. Go to **Pipelines** → **Library** → **+ Variable group**
2. Create a group named `policy-gate-vars`
3. Add the following variables:

| Variable | Value | Secret? |
|----------|-------|---------|
| `ARM_SUBSCRIPTION_ID` | Your Azure subscription ID | No |
| `ARM_CLIENT_ID` | Service Principal client ID | No |
| `ARM_CLIENT_SECRET` | Service Principal secret | ✅ Yes |
| `ARM_TENANT_ID` | Azure AD tenant ID | No |
| `AZURE_STORAGE_CONNECTION_STRING` | Connection string from Step 3 | ✅ Yes |

4. Save the variable group

### Link Variable Group to Pipeline

Edit `azure-pipelines.yml` and add under the `variables` section:

```yaml
variables:
  - group: policy-gate-vars
  # ... existing variables ...
```

Alternatively, set these variables directly in the pipeline settings UI:
- **Pipelines** → select pipeline → **Edit** → **Variables**

### Enable System.AccessToken

The pipeline uses `$(System.AccessToken)` to post PR comments. Ensure it has the right permissions:

1. Go to **Project Settings** → **Repositories** → select your repo
2. Under **Security**, find **Build Service** user
3. Grant **Contribute to pull requests** permission

---

## 7. Create the Pipeline

1. Go to **Pipelines** → **New Pipeline**
2. Select **Azure Repos Git**
3. Select your repository
4. Choose **Existing Azure Pipelines YAML file**
5. Select `/azure-pipelines.yml`
6. Click **Run** (or save without running)

---

## 8. Configure Branch Protection

This is the key step that makes the policy gate actually block PRs:

### 8a. Set Up Branch Policy

1. Go to **Repos** → **Branches**
2. Click the **⋮** menu next to `main` → **Branch policies**
3. Under **Build Validation**, click **+ Add build policy**:

| Setting | Value |
|---------|-------|
| Build pipeline | Select your `azure-policy-gate` pipeline |
| Trigger | Automatic |
| Policy requirement | Required |
| Build expiration | Immediately when `main` is updated |
| Display name | `Policy Gate Check` |

4. Save

### 8b. Additional Recommended Policies

Under the same branch policies page:

- ✅ **Require a minimum number of reviewers** — at least 1
- ✅ **Check for linked work items** — optional
- ✅ **Check for comment resolution** — required
- ✅ **Limit merge types** — squash merge recommended

### How It Works

When a PR is created or updated that touches any file under `terraform/`:

1. The pipeline **automatically triggers**
2. It runs `terraform plan` → converts to JSON
3. The Python policy engine evaluates the plan
4. Violations are **posted as a comment** on the PR
5. If any **HIGH** severity violations exist → pipeline **fails** → PR is **blocked**
6. All violations are **logged to Table Storage** for audit

The PR can only merge when:
- All HIGH severity violations are fixed
- The pipeline passes (exit code 0)

---

## 9. Test the Setup

### Create a Test PR

```bash
# Create a feature branch
git checkout -b test/policy-violations

# The demo infrastructure already has violations — 
# just make a small change to trigger the pipeline
echo "# trigger" >> terraform/demo/main.tf

# Push and create a PR
git add -A
git commit -m "test: trigger policy gate"
git push origin test/policy-violations
```

Then create a PR in Azure DevOps targeting `main`. The pipeline should:

1. ✅ Run automatically
2. ✅ Detect violations in the demo infrastructure
3. ✅ Post a comment with the violation table
4. ❌ Fail the pipeline (because HIGH violations exist)
5. 🚫 Block the PR from merging

### Verify Table Storage

```bash
az storage entity query \
  --table-name PolicyViolations \
  --account-name stpolicygatestate \
  --query "items[].{PR:PRNumber, Rule:RuleId, Severity:Severity, Outcome:Outcome}"
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Pipeline doesn't trigger on PR | Check PR path filters match `terraform/**` |
| Terraform init fails | Verify backend storage account exists and SP has access |
| PR comment not posted | Ensure `System.AccessToken` has contribute-to-PR permission |
| Table Storage write fails | Check `AZURE_STORAGE_CONNECTION_STRING` is correct |
| SP authentication fails | Verify `ARM_*` variables match the SP credentials |
