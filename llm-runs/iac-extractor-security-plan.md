# IaC Extractor Security & Resilience Plan

**Date**: 2026-03-07  
**Status**: Implementation in progress  

## Objective

Extend the IaC extraction pipeline to capture security and resilience details from cloud infrastructure files:
- Cloud regions, availability zones, secret key store use, encryption-at-rest
- K8s / Terraform / Bicep / CloudFormation / GCP DM — security, resilience config
- IAM roles, service accounts, managed identities, role bindings

---

## Phase 1 — Schema (`src/xelo/models.py` + `src/xelo/types.py`)

### New `ComponentType`

```python
IAM = "IAM"
```

Covers: IAM roles, IAM policies, K8s ServiceAccounts, GCP service accounts, Azure managed identities, subscription/project-level role assignments.

### `NodeMetadata` — new IaC security + IAM fields

| Field | Type | Description |
|-------|------|-------------|
| `cloud_region` | `str \| None` | e.g. `"us-east-1"`, `"eastus"`, `"us-central1"` |
| `availability_zones` | `list[str] \| None` | e.g. `["us-east-1a","us-east-1b"]` |
| `secret_store` | `str \| None` | `"aws_secrets_manager"`, `"azure_key_vault"`, `"gcp_secret_manager"`, `"hashicorp_vault"`, `"k8s_secret"` |
| `encryption_at_rest` | `bool \| None` | Explicitly configured |
| `encryption_key_ref` | `str \| None` | KMS ARN, Key Vault URI, CMEK ref |
| `runs_as_root` | `bool \| None` | Container user risk flag |
| `has_health_check` | `bool \| None` | Dockerfile `HEALTHCHECK` or K8s probes |
| `has_resource_limits` | `bool \| None` | K8s `resources.limits` present |
| `ha_mode` | `str \| None` | `"multi-az"`, `"replicated"`, `"single"` |
| `iam_type` | `str \| None` | `"role"`, `"policy"`, `"service_account"`, `"managed_identity"`, `"role_binding"` |
| `principal` | `str \| None` | ARN, email, or object ID of the principal |
| `permissions` | `list[str] \| None` | Actions/scopes granted (up to 20) |
| `iam_scope` | `str \| None` | `"project"`, `"subscription"`, `"cluster"`, `"namespace"`, `"resource"` |
| `trust_principals` | `list[str] \| None` | AWS trust relationship / K8s subjects |

### `ScanSummary` — new aggregate fields

| Field | Type | Description |
|-------|------|-------------|
| `secret_stores` | `list[str]` | Deduped secret store names |
| `availability_zones` | `list[str]` | All AZs referenced |
| `encryption_at_rest_coverage` | `bool` | Any resource with encryption-at-rest |
| `security_findings` | `list[str]` | `"container_runs_as_root"`, `"missing_health_check"`, etc. |
| `iam_principals` | `list[str]` | Discovered IAM role ARNs / service account names |
| `service_accounts` | `list[str]` | K8s ServiceAccounts + GCP SA emails |

---

## Phase 2 — New `src/xelo/adapters/iac.py`

Five adapter classes:

### `K8sAdapter`
Trigger: YAML with `apiVersion:` + `kind:` keys.
- Workload kinds → `DEPLOYMENT` node with security context, probes, limits, HA
- RBAC kinds → `IAM` node with permissions, subjects, scope

### `TerraformAdapter`
Trigger: `.tf` files.
- DEPLOYMENT node per file: provider, region, AZs, encryption, secret stores
- IAM nodes: `aws_iam_role`, `aws_iam_policy`, `google_service_account`, `google_project_iam_*`, `azurerm_role_assignment`, `azurerm_user_assigned_identity`

### `CloudFormationAdapter`
Trigger: YAML/JSON with `AWSTemplateFormatVersion` or `Resources.*.Type` starting with `AWS::`.
- DEPLOYMENT node: multi-AZ, encryption, KMS, secret stores
- IAM nodes: `AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::InstanceProfile`

### `BicepAdapter`
Trigger: `.bicep` files.
- DEPLOYMENT node: region, zones, Key Vault, encryption settings
- IAM nodes: `Microsoft.ManagedIdentity/userAssignedIdentities`, `Microsoft.Authorization/roleAssignments`, `Microsoft.Authorization/policyAssignments`

### `GcpDeploymentManagerAdapter`
Trigger: YAML `resources:` list with `gcp-types/` or `*.v1.*` type prefixes; also `.jinja` files.
- DEPLOYMENT node: region, zones, KMS, Secret Manager
- IAM nodes: `iam.v1.serviceAccounts`, `cloudresourcemanager` IAM bindings

---

## Phase 3 — Dockerfile security (`src/xelo/adapters/dockerfile.py`)

- `USER` instruction → `runs_as_root = True/False` in extras
- `HEALTHCHECK` → `has_health_check = True/False` in extras
- `ARG`/`ENV` with secret-like names → `security_findings: ["secrets_in_build_args"]`
- >1 `FROM` → `extras["multi_stage_build"] = True`

---

## Phase 4 — Aggregation (`src/xelo/core/application_summary.py`)

Post-assembly from DEPLOYMENT + IAM node metadata:
- `secret_stores`, `availability_zones`, `encryption_at_rest_coverage`
- `iam_principals`, `service_accounts`
- `security_findings`: root containers, missing probes, missing limits, wildcard permissions

---

## Phase 5 — Config + Extractor wiring

- `config.py`: add `.bicep`, `.jinja` to `include_extensions` default
- `extractor.py`: add `.bicep`, `.jinja` to `_IAC_EXTENSIONS`; wire 5 new adapters; pass new summary fields

---

## Phase 6 — Schema regen + docs

- Regenerate `src/xelo/schemas/aibom.schema.json`
- Bump `schema_version` → `1.2.0`
- Update `docs/aibom-schema.md`

---

## File touch map

| File | Change |
|------|--------|
| `src/xelo/types.py` | Add `IAM = "IAM"` |
| `src/xelo/models.py` | 14 new `NodeMetadata` fields, 6 new `ScanSummary` fields |
| `src/xelo/adapters/iac.py` | **New** — 5 adapter classes |
| `src/xelo/adapters/dockerfile.py` | Add USER/HEALTHCHECK/secrets detection |
| `src/xelo/core/application_summary.py` | Aggregate new fields |
| `src/xelo/config.py` | Add `.bicep`, `.jinja` to `include_extensions` |
| `src/xelo/extractor.py` | Wire adapters + summary pass-through |
| `src/xelo/schemas/aibom.schema.json` | Regenerated |
| `docs/aibom-schema.md` | Document new fields |
