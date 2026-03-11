# AI SBOM Schema

This document explains the structure of the AI SBOM (Software Bill of Materials) document produced by Xelo. Every field maps directly to the Pydantic models in `src/xelo/models.py`. The canonical JSON Schema is at `src/xelo/schemas/aibom.schema.json` and can be printed with `xelo schema`.

## Top-level Structure

```json
{
  "schema_version": "1.3.0",
  "generated_at": "2026-03-07T08:00:00Z",
  "generator": "xelo",
  "target": "./my-repo",
  "nodes": [...],
  "edges": [...],
  "deps":  [...],
  "summary": {...}
}
```

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | SBOM schema semver; bump when format changes |
| `generated_at` | ISO 8601 datetime | UTC timestamp of the scan |
| `generator` | string | Always `"xelo"` |
| `target` | string | Repository URL or local path scanned |
| `nodes` | array of Node | Detected AI components — the main payload |
| `edges` | array of Edge | Directed relationships between nodes |
| `deps` | array of PackageDep | Package manifest dependencies |
| `summary` | ScanSummary | Scan-level roll-up metadata |

---

## Node

A node is one detected AI component. Nodes are the main thing you work with.

```json
{
  "id": "3f4a1c2d-...",
  "name": "ResearchAgent",
  "component_type": "AGENT",
  "confidence": 0.95,
  "metadata": { ... },
  "evidence": [ ... ]
}
```

### `component_type` values

| Type | What it represents |
| --- | --- |
| `AGENT` | An agentic orchestrator — LangGraph graph, CrewAI crew, AutoGen agent, OpenAI Agent, etc. |
| `MODEL` | An LLM or embedding model reference — e.g. `gpt-4o`, `claude-3-5-sonnet`, `text-embedding-3-small` |
| `TOOL` | A function tool or MCP tool wired to an agent |
| `PROMPT` | A system instruction or prompt template; full content preserved in `metadata.extras.content` |
| `DATASTORE` | A vector store, database, or cache — Chroma, Pinecone, Redis, PostgreSQL, etc. |
| `GUARDRAIL` | A content filter or safety validator — Guardrails AI validators, NeMo Guardrails, etc. |
| `AUTH` | An authentication node — OAuth2, Bearer, API key, JWT, MCP auth provider |
| `PRIVILEGE` | A capability grant — `db_write`, `filesystem_write`, `code_execution`, `network_out`, etc. |
| `CONTAINER_IMAGE` | A container image reference from a Dockerfile — carries image name, tag, digest, and security posture |
| `DEPLOYMENT` | An IaC-derived deployment unit — Kubernetes workload, Terraform resource, CloudFormation stack, GitHub Actions workflow, etc. |
| `IAM` | An IAM entity detected in IaC — AWS role/policy, GCP service account, Azure managed identity, K8s role/ClusterRole |
| `FRAMEWORK` | An AI framework detected without a more specific type — used when a framework is present but no individual agents were found |
| `API_ENDPOINT` | An exposed API route or MCP endpoint |

### `confidence`

A float between 0 and 1. Values above 0.85 indicate high-confidence AST-derived detection. Values between 0.5–0.85 are usually regex-based. Below 0.5 is inferred or uncertain.

### `metadata`

All typed metadata fields are optional (null when not applicable). Fields relevant to each node type:

**For MODEL nodes:**

| Field | Description |
| --- | --- |
| `model_name` | LLM or embedding model identifier, e.g. `"gpt-4o-mini"` |
| `framework` | Framework the model is used through, e.g. `"openai_agents"`, `"langgraph"` |
| `extras.provider` | Cloud/API provider — `"openai"`, `"anthropic"`, `"google"`, `"bedrock"`, etc. |
| `extras.model_family` | Normalised family — `"gpt-4"`, `"claude-3"`, `"gemini"` |

**For DATASTORE nodes:**

| Field | Description |
| --- | --- |
| `datastore_type` | Technology — `"chromavector"`, `"pinecone"`, `"postgres"`, `"redis"`, etc. |
| `data_classification` | Union of classification labels — `["PHI", "PII"]` |
| `classified_tables` | SQL table or Python model names that carry classified fields |
| `classified_fields` | Per-table mapping of field names to labels: `{"patients": ["name", "dob"]}` |

**For AUTH / API_ENDPOINT / MCP nodes:**

| Field | Description |
| --- | --- |
| `auth_type` | Mechanism — `"oauth2"`, `"bearer"`, `"api_key"`, `"jwt"` |
| `auth_class` | Provider class name, e.g. `"BearerAuthProvider"` |
| `transport` | Protocol — `"sse"`, `"streamable-http"`, `"stdio"` |
| `server_name` | MCP server display name |
| `endpoint` | Address — `"0.0.0.0:8080 (sse)"`, `"/chat"` |
| `method` | HTTP method — `"GET"`, `"POST"` |

**For PRIVILEGE nodes:**

| Field | Description |
| --- | --- |
| `privilege_scope` | Capability label — `"db_write"`, `"filesystem_write"`, `"code_execution"`, `"network_out"`, `"email_out"`, `"social_media_out"`, `"admin"`, `"rbac"` |

**For CONTAINER_IMAGE nodes (Dockerfile):**

| Field | Description |
| --- | --- |
| `image_name` | e.g. `"python"` |
| `image_tag` | e.g. `"3.12-slim"` |
| `image_digest` | e.g. `"sha256:abc…"` |
| `registry` | e.g. `"docker.io"`, `"gcr.io"` |
| `base_image` | Full reference — `"python:3.12-slim"` |
| `runs_as_root` | `true` when the container runs as root (UID 0), `false` when non-root |
| `has_health_check` | `true` when a `HEALTHCHECK` instruction is present in the Dockerfile |
| `has_resource_limits` | `true` when Kubernetes resource limits are defined for the container |

**For DEPLOYMENT nodes (IaC — K8s, Terraform, CloudFormation, GitHub Actions, etc.):**

| Field | Description |
| --- | --- |
| `cloud_region` | Cloud region — e.g. `"us-east-1"`, `"eastus"`, `"us-central1"` |
| `availability_zones` | AZs configured — e.g. `["us-east-1a", "us-east-1b"]` |
| `secret_store` | Secret management service — `"aws_secrets_manager"`, `"azure_key_vault"`, `"gcp_secret_manager"`, `"hashicorp_vault"`, `"k8s_secret"`, `"github_actions_secret"` |
| `encryption_at_rest` | `true` when encryption-at-rest is explicitly configured |
| `encryption_key_ref` | KMS key ARN, Key Vault URI, or CMEK resource reference |
| `ha_mode` | HA topology: `"multi-az"`, `"replicated"`, or `"single"` |
| `runs_as_root` | `true` when the pod/container security context runs as root |
| `has_health_check` | `true` when a liveness or readiness probe is configured |
| `has_resource_limits` | `true` when Kubernetes resource limits are defined |

**For IAM nodes (IaC — AWS roles/policies, GCP service accounts, Azure managed identities, K8s RBAC):**

| Field | Description |
| --- | --- |
| `iam_type` | Entity kind: `"role"`, `"policy"`, `"service_account"`, `"managed_identity"`, `"role_binding"` |
| `principal` | ARN, email, or object ID of the IAM principal |
| `permissions` | Actions or scopes granted (up to 20 entries) — e.g. `["s3:GetObject", "s3:PutObject"]` |
| `iam_scope` | Scope of the binding: `"project"`, `"subscription"`, `"cluster"`, `"namespace"`, `"resource"` |
| `trust_principals` | Principals trusted to assume this role — AWS trust policy subjects or K8s binding subjects |

**For PROMPT nodes:**

| Field | Description |
| --- | --- |
| `extras.content` | Full prompt text (may contain `{variable}` placeholders) |
| `extras.role` | Detected role — `"system"`, `"user"`, `"assistant"`, or `"unspecified"` |
| `extras.char_count` | Character length of the content |
| `extras.is_template` | `true` when `{variable}` placeholders are present |
| `extras.template_variables` | List of variable names found in the template, e.g. `["query", "context"]` |
| `extras.message_type` | Source class — e.g. `"ChatPromptTemplate"`, `"SystemMessage"`, `"PromptTemplate"` |
| `extras.injection_risk_score` | Float 0–1 estimating prompt-injection risk (TypeScript adapter only) |

**For MODEL nodes:**

| Field | Description |
| --- | --- |
| `extras.provider` | Cloud/API provider — `"openai"`, `"anthropic"`, `"google"`, `"bedrock"`, etc. |
| `extras.model_family` | Normalised family — `"gpt-4"`, `"claude-3"`, `"gemini"` |

**For all nodes (when LLM enrichment is enabled with `--llm`):**

| Field | Description |
| --- | --- |
| `extras.llm_verified` | `true` when the LLM verification pass confirmed the detection |
| `extras.llm_verification_reason` | One-sentence justification from the LLM |
| `extras.llm_confidence` | LLM-assigned confidence score [0, 1], replacing the original if higher |
| `extras.confidence_breakdown` | Object with keys `"ast"` and `"llm"` showing pre/post-enrichment scores |

**For all nodes:**

| Field | Description |
| --- | --- |
| `deployment_target` | Cloud target — `"aws"`, `"gcp"`, `"kubernetes"` |
| `extras` | Adapter-specific key/value pairs not covered by the typed fields above |

### `evidence`

Each node carries one or more evidence items explaining why Xelo detected it:

```json
{
  "kind": "ast_instantiation",
  "confidence": 0.95,
  "detail": "crewai_adapter: Agent(role='researcher', ...)",
  "location": { "path": "src/agents.py", "line": 42 }
}
```

| Field | Description |
| --- | --- |
| `kind` | Detection method: `"ast"`, `"ast_instantiation"`, `"regex"`, `"config"`, `"iac"`, `"inferred"` |
| `confidence` | Evidence-level confidence [0, 1] |
| `detail` | `"<adapter>: <evidence_kind>"` for PROMPT nodes (full content is in `metadata.extras.content`); `"<adapter>: <snippet>"` (up to 500 chars) for all other node types |
| `location.path` | Repo-relative file path |
| `location.line` | 1-based line number, if known |

---

## Edge

An edge represents a directed relationship between two nodes.

```json
{
  "source": "3f4a1c2d-...",
  "target": "a7b2e9f0-...",
  "relationship_type": "CALLS"
}
```

### `relationship_type` values

| Type | Meaning |
| --- | --- |
| `USES` | Agent or framework uses a model |
| `CALLS` | Agent calls a tool |
| `ACCESSES` | Agent or model accesses a datastore |
| `PROTECTS` | Guardrail protects an agent or model |
| `DEPLOYS` | Deployment artifact deploys an agent or framework |

Explicit edges come from AST analysis. When no explicit edges are found, Xelo adds inferred fallback edges (e.g. agents → tools of the same file).

---

## PackageDep

Standard package manifest entries, scanned recursively at any depth.

```json
{
  "name": "langchain-core",
  "version_spec": ">=0.3.0",
  "purl": "pkg:pypi/langchain-core@0.3.51",
  "source_file": "pyproject.toml",
  "ecosystem": "pypi"
}
```

---

## ScanSummary

High-level roll-up attached to every document.

| Field | Type | Description |
| --- | --- | --- |
| `use_case` | string | Natural-language description of what the app does (deterministic rule-based; enriched by LLM when enabled) |
| `frameworks` | list[string] | Detected framework names — `["langgraph", "openai_agents"]` |
| `modalities` | list[string] | I/O modalities in upper-case — `["TEXT", "VOICE", "IMAGE"]` |
| `modality_support` | dict | Detailed flags — `{"text": true, "voice": false}` |
| `api_endpoints` | list[string] | API route paths — `["/chat", "/health"]` |
| `deployment_platforms` | list[string] | Cloud/CI platforms — `["AWS", "GCP"]` |
| `regions` | list[string] | Cloud regions — `["us-east-1"]` |
| `environments` | list[string] | Deployment envs — `["prod", "staging"]` |
| `deployment_urls` | list[string] | Canonical URLs from IaC/workflow files |
| `iac_accounts` | list[string] | Cloud account / project IDs from IaC |
| `node_counts` | dict | Count per type — `{"AGENT": 3, "MODEL": 2, "TOOL": 5}` |
| `secret_stores` | list[string] | Deduplicated secret management services across all IaC files — e.g. `["aws_secrets_manager"]` |
| `availability_zones` | list[string] | All cloud AZs referenced in IaC — e.g. `["us-east-1a", "us-east-1b"]` |
| `encryption_at_rest_coverage` | bool | `true` when at least one IaC resource has encryption-at-rest configured |
| `security_findings` | list[string] | Notable security/resilience issues detected across IaC and container config — e.g. `["container_runs_as_root", "missing_health_check", "no_resource_limits", "secrets_in_env_vars", "overly_permissive_iam"]` |
| `iam_principals` | list[string] | IAM role ARNs, GCP service account emails, and Azure managed identity names |
| `service_accounts` | list[string] | K8s ServiceAccount names and GCP/Azure service account identifiers |
| `iac_security_summary` | string\|null | LLM-generated security briefing covering deployment posture, IAM, secret management, encryption, HA, and CI/CD risks. Populated only when LLM enrichment is enabled (`--llm`). |
| `data_classification` | list[string] | Union of all classification labels — `["PHI", "PII"]` |
| `classified_tables` | list[string] | All SQL tables / Python models carrying PII or PHI |

---

## Data Classification

Xelo classifies PII and PHI by analysing SQL `CREATE TABLE` statements and Python model definitions (Pydantic `BaseModel`, SQLAlchemy ORM, `@dataclass`). Classification results appear in two places:

1. On each DATASTORE node — `metadata.classified_tables` and `metadata.classified_fields` show which tables/fields were flagged.
2. In `summary.data_classification` and `summary.classified_tables` — a project-wide roll-up.

**Classification labels:**
- `PII` — name, email, phone, address, date of birth, SSN, passport, financial fields, IP address, password
- `PHI` — medical record numbers, diagnosis, medication, lab results, insurance ID, vital signs, mental health, allergies

---

## JSON Schema

The machine-readable JSON Schema (draft 2020-12) is embedded in the package:

```bash
xelo schema                    # print to stdout
xelo schema --output schema.json   # write to file
xelo validate my-sbom.json     # validate a document
```

Schema `$id`: `https://nuguard.ai/schemas/aibom/1.3.0/aibom.schema.json`

The schema is generated directly from the Pydantic models and is always in sync with the code.
