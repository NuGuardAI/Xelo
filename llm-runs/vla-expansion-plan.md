# VLA Structural Rules Expansion Plan
## IaC, Auth, Privilege, Data Security & Resilience

**Date**: 2026-03-07  
**Target file**: `src/xelo/toolbox/plugins/vulnerability.py`  
**Schema version context**: 1.3.0 (post GitHub Actions adapter + IaC extraction)

---

## Context

The IaC extraction work added typed fields to `NodeMetadata` and `ScanSummary` that
the existing VLA-001–009 structural rules do not yet consume. This plan defines 12 new
rules and 3 enhancements to existing rules, organized by concern area.

---

## Signal inventory available in SBOM

### `NodeMetadata` typed fields (all nullable)

| Field | Type | Populated by |
|---|---|---|
| `secret_store` | `str` | K8s, TF, CFN, Bicep, GCP DM, GHA |
| `encryption_at_rest` | `bool` | TF, CFN, Bicep |
| `encryption_key_ref` | `str` | TF, CFN, Bicep (CMK/BYOK) |
| `runs_as_root` | `bool` | K8s, Dockerfile |
| `has_health_check` | `bool` | K8s, Dockerfile |
| `has_resource_limits` | `bool` | K8s |
| `ha_mode` | `str` | K8s (`multi-az`, `replicated`), GHA (`replicated`) |
| `availability_zones` | `list[str]` | TF |
| `iam_type` | `str` | All IAM nodes |
| `permissions` | `list[str]` | All IAM nodes (`verb:resource` or `service:action`) |
| `iam_scope` | `str` | `cluster`, `namespace`, `account`, `project`, `subscription` |
| `trust_principals` | `list[str]` | Role bindings, OIDC trusts |
| `deployment_target` | `str` | `kubernetes`, `aws`, `azure`, `gcp`, `github-actions` |
| `workflow_triggers` | `list[str]` in `extras` | GHA |
| `uses_oidc` | `bool` in `extras` | GHA |
| `cloud_providers` | `list[str]` in `extras` | GHA |

### `ScanSummary` aggregate fields

`secret_stores`, `availability_zones`, `encryption_at_rest_coverage`,
`security_findings` (`container_runs_as_root`, `missing_health_check`,
`no_resource_limits`, `overly_permissive_iam`), `iam_principals`, `service_accounts`

---

## New rules

### Encryption & Data Security

**VLA-010 — CRITICAL: PHI/PII workload with no encryption at rest**
- **Trigger**: `data_classification` contains PHI/PII AND `summary.encryption_at_rest_coverage == False`
- **Rationale**: HIPAA §164.312(a)(2)(iv) requires encryption of ePHI at rest.
- **Remediation**: Enable `encrypted = true` in Terraform, K8s encryption providers, EBS/Azure Disk/GCS CMEK.

**VLA-011 — HIGH: PHI/PII encrypted at rest without CMK/BYOK**
- **Trigger**: PHI/PII + `encryption_at_rest_coverage == True` + no DEPLOYMENT node has `encryption_key_ref` set
- **Rationale**: Provider-managed keys cannot be revoked by the customer; NIST CSF DE.CM-5 recommends BYOK.
- **Remediation**: Configure `kms_key_id`, `disk_encryption_set_id`, or `crypto_key_id`.

**VLA-012 — HIGH: Secrets in env vars or no secret store**
- **Trigger**: `"secrets_in_env_vars"` in `summary.security_findings` OR (no secret stores AND DEPLOYMENT nodes exist)
- **Rationale**: Env-var secrets appear in process lists, container inspection, and CI logs.
- **Remediation**: Migrate to AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or Vault. Use GHA OIDC instead of static secrets.

**VLA-013 — MEDIUM: No secret management service across entire deployment**
- **Trigger**: `summary.secret_stores` is empty AND at least one DEPLOYMENT node exists AND `secrets_in_env_vars` NOT already fired (VLA-012 covers that path).
- **Rationale**: Absence of any secret store implies credentials in config files or container images.

### IAM & Privilege

**VLA-014 — HIGH: Overly permissive IAM with PHI in scope**
- **Trigger**: PHI/PII + (`"overly_permissive_iam"` in security_findings OR any IAM `permissions` contains `"*"`)
- **Rationale**: IAM wildcards on PHI workloads violate HIPAA minimum-necessary (§164.502(b)).
- **Remediation**: Replace `*` verbs with explicit action lists; use K8s RBAC with specific `resources:`.

**VLA-015 — HIGH: Cluster-scoped IAM role/service-account without permission boundary**
- **Trigger**: Any IAM node where `iam_scope == "cluster"` AND `iam_type in ("role", "service_account")` AND (permissions contain `"*"` OR permissions absent)
- **Rationale**: Cluster-scoped K8s resources can be exploited for lateral movement.
- **Remediation**: Use namespace-scoped Role + RoleBinding; apply K8s RBAC least-privilege.

**VLA-016 — HIGH: GitHub Actions workflow accessing cloud without OIDC**
- **Trigger**: Any GHA DEPLOYMENT node where `uses_oidc == False` AND `cloud_providers` non-empty
- **Rationale**: Static credentials in GitHub secrets cannot be auto-rotated and are exposed on repo compromise.
- **Remediation**: Replace `AWS_ACCESS_KEY_ID`/`AZURE_CREDENTIALS`/`GCP_SA_KEY` with OIDC federation actions.

**VLA-017 — MEDIUM: GitHub Actions with write/admin permissions and PHI in scope**
- **Trigger**: PHI/PII + any GHA DEPLOYMENT node has `permissions` containing `":write"` or `"admin"`
- **Rationale**: Write-permissioned workflows combined with PHI create a data-exfiltration vector.
- **Remediation**: Restrict `permissions:` to `contents: read`, `id-token: write` only.

### Resilience

**VLA-018 — HIGH: Single-AZ deployment for AI service handling PHI**
- **Trigger**: PHI/PII + `summary.availability_zones` empty + no DEPLOYMENT node has `ha_mode` set
- **Rationale**: HIPAA §164.312(a)(2)(ii) contingency plan requires ePHI availability; single-AZ has no failover.
- **Remediation**: Configure `availability_zones` in Terraform, K8s `topologySpreadConstraints`, or RDS `multi_az = true`.

**VLA-019 — MEDIUM: AI workloads without health checks**
- **Trigger**: `"missing_health_check"` in `summary.security_findings` AND any AI node (AGENT/MODEL/FRAMEWORK) exists
- **Rationale**: Without probes, failed AI containers stay in the load-balancer rotation.
- **Remediation**: Add `livenessProbe`/`readinessProbe` in K8s and `HEALTHCHECK` in Dockerfile.

**VLA-020 — LOW: AI workloads without resource limits**
- **Trigger**: `"no_resource_limits"` in `summary.security_findings` AND any DEPLOYMENT node exists
- **Rationale**: LLM inference can consume unbounded CPU/memory; limits also enforce cost governance.
- **Remediation**: Set `resources.limits.memory`/`.cpu` in K8s container specs.

### Container Security

**VLA-021 — HIGH: Containers running as root**
- **Trigger**: `"container_runs_as_root"` in `summary.security_findings` OR any CONTAINER_IMAGE/DEPLOYMENT node has `runs_as_root == True`
- **Rationale**: Root containers can write to the host filesystem on escape; NIST SP 800-190 recommends non-root.
- **Remediation**: Add `USER nonroot` to Dockerfile; set `securityContext.runAsNonRoot: true`.

---

## Enhancements to existing rules

**VLA-003 enhancement**: also fire when PHI API paths exist AND there are IAM nodes
with cluster/account scope (an over-privileged role bypasses endpoint-level auth).

**VLA-004 enhancement**: cross-check whether the PRIVILEGE node has an associated
IAM node with `iam_scope == "cluster"` and wildcard permissions — escalate severity
from HIGH to CRITICAL when PHI is present.

**VLA-009 enhancement**: also check whether GHA workflows use `pull_request` trigger
without branch restrictions when the repo has API code (extractable from `workflow_triggers`).

---

## Rule severity summary

| ID | Severity | Title |
|---|---|---|
| VLA-010 | CRITICAL | PHI workload — no encryption at rest |
| VLA-011 | HIGH | PHI encrypted at rest — no CMK/BYOK |
| VLA-012 | HIGH | Secrets in env vars or no secret store |
| VLA-013 | MEDIUM | No secret management service |
| VLA-014 | HIGH | Overly permissive IAM with PHI |
| VLA-015 | HIGH | Cluster-scoped role without permission boundary |
| VLA-016 | HIGH | GHA accesses cloud without OIDC |
| VLA-017 | MEDIUM | GHA write permissions with PHI |
| VLA-018 | HIGH | Single-AZ deployment with PHI |
| VLA-019 | MEDIUM | AI workloads without health checks |
| VLA-020 | LOW | AI workloads without resource limits |
| VLA-021 | HIGH | Containers running as root |

---

## Implementation notes

1. Add helpers: `_depl_meta(node)`, `_gha_nodes(nodes)`, `_iam_nodes_list(nodes)`,
   `_has_wildcard_perm(permissions)` to `vulnerability.py`.
2. Insert new rules at the end of `_RULES` list in severity order (CRITICAL first).
3. VLA-019, VLA-020, VLA-021 consume `summary.security_findings` tags
   — no redundant node iteration.
4. PHI guard: rules VLA-010, VLA-011, VLA-014, VLA-017, VLA-018 only fire when
   PHI/PII confirmed in `data_classification`.
5. No new dependencies required — all signals are in the SBOM dict.
