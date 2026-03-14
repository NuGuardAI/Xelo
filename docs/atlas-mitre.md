# MITRE ATLAS Annotation

**Plugin name**: `atlas`  
**CLI command**: `xelo plugin run atlas <SBOM>`  
**Xelo version**: 0.7.0+  
**ATLAS version**: v2

---

## Overview

The `atlas` plugin annotates every finding in your AI SBOM with [MITRE ATLAS v2](https://atlas.mitre.org) technique IDs, tactic mappings, and recommended mitigations. It runs in two modes:

| Mode | How to invoke | What it adds |
|---|---|---|
| **Static** (default) | `xelo plugin run atlas sbom.json` | ATLAS technique IDs + mitigations (fully offline) |
| **LLM-enriched** | `--config llm=true --config llm_model=…` | Static output + CVE context (OSV + Grype) + per-finding `llm_summary` + executive `llm_summary` |

Both modes run the same two static passes before any LLM work:

- **Pass 1 — VLA signal mapping**: runs the structural VLA rules and maps each `VLA-xxx` finding to one or more ATLAS techniques via a static lookup table.
- **Pass 2 — Native ATLAS graph checks**: inspects the SBOM node/edge graph directly for patterns that map to ATLAS techniques but aren't covered by a single VLA rule (NC-001 through NC-004).

---

## Quick start

```bash
# Scan a repository first
xelo scan https://github.com/NuGuardAI/openai-cs-agents-demo --output sbom.json

# Static ATLAS annotation — JSON output (offline, instant)
xelo plugin run atlas sbom.json --output atlas.json

# Static ATLAS annotation — Markdown output (offline, human-readable)
xelo plugin run atlas sbom.json \
  --config format=markdown \
  --output atlas-report.md

# LLM-enriched — JSON output (OSV/Grype CVEs + narrative summaries)
xelo plugin run atlas sbom.json \
  --config llm=true \
  --config llm_model=vertex_ai/gemini-3.1-flash-lite-preview \
  --output atlas-llm.json

# LLM-enriched — Markdown output
xelo plugin run atlas sbom.json \
  --config llm=true \
  --config llm_model=vertex_ai/gemini-3.1-flash-lite-preview \
  --config format=markdown \
  --output atlas-llm-report.md
```

For LLM mode the following environment variables are used automatically:

| Env var | Purpose |
|---|---|
| `GEMINI_API_KEY` | Vertex AI / Gemini API key (Vertex AI path) |
| `OPENAI_API_KEY` | OpenAI API key (via litellm) |
| `ANTHROPIC_API_KEY` | Anthropic API key (via litellm) |

You can also pass the key inline: `--config llm_api_key=<key>`.

---

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--config format=markdown` | — | Render output as Markdown instead of JSON (no LLM required) |
| `--config llm=true` | false | Enable LLM enrichment (OSV/Grype CVEs + narrative summaries) |
| `--config llm_model=<model>` | `gpt-4o-mini` | Any litellm model string or `vertex_ai/<model>` |
| `--config llm_api_key=<key>` | env var | API key for the LLM provider |
| `--config llm_api_base=<url>` | provider default | Base URL override (Azure AI Foundry, etc.) |
| `--config llm_budget_tokens=<n>` | `50000` | Max tokens to spend on LLM calls |
| `--output <file>` | stdout | Write output to file |

---

## Native ATLAS checks (Pass 2)

These structural checks run against the SBOM graph on every invocation, regardless of LLM mode:

| Check ID | Title | Techniques triggered |
|---|---|---|
| ATLAS-NC-001 | External MODEL without integrity hash | AML.T0010, AML.T0048 |
| ATLAS-NC-002 | Writable DATASTORE reachable by unguarded model/agent | AML.T0020 |
| ATLAS-NC-003 | MODEL–DEPLOYMENT path without AUTH node | AML.T0035 |
| ATLAS-NC-004 | AGENT or TOOL with outbound external-API capability | AML.T0036, AML.T0024 |

---

## Output schema

```json
{
  "status": "warning",
  "tool": "atlas_annotate",
  "message": "4 ATLAS-annotated finding(s) across 2 unique technique(s)",
  "details": {
    "atlas_version": "v2",
    "basis": "static",
    "total_findings": 4,
    "techniques_identified": ["AML.T0037", "AML.T0024"],
    "tactics_covered": ["Collection", "Exfiltration"],
    "confidence_breakdown": { "HIGH": 2, "MEDIUM": 0, "LOW": 0 },
    "llm_summary": "…executive narrative… (LLM mode only)",
    "findings": [
      {
        "rule_id": "VLA-002",
        "severity": "CRITICAL",
        "title": "…",
        "affected": ["gpt-4.1-mini"],
        "remediation": "…",
        "cve_context": [ … ],
        "atlas": {
          "atlas_version": "v2",
          "llm_summary": "…per-finding narrative… (LLM mode only)",
          "techniques": [
            {
              "technique_id": "AML.T0037",
              "technique_name": "Data from Information Repositories",
              "tactic_id": "AML.TA0008",
              "tactic_name": "Collection",
              "atlas_url": "https://atlas.mitre.org/techniques/AML.T0037",
              "confidence": "HIGH",
              "basis": "static",
              "mitigations": [ … ]
            }
          ]
        }
      }
    ]
  }
}
```

`cve_context` and `llm_summary` fields only appear when `--config llm=true`.

---

## Example: OpenAI CS Agents Demo

**Repository**: [NuGuardAI/openai-cs-agents-demo](https://github.com/NuGuardAI/openai-cs-agents-demo)  
**SBOM**: 29 nodes, 36 edges — 5 agents, 2 guardrails, `gpt-4.1-mini`, PII data classified, Azure deployment via GitHub Actions

### Static mode (offline)

```bash
xelo plugin run atlas output/openai-cs-demo/sbom.json \
  --config format=markdown \
  --output atlas-report.md
```

**Console output:**

```text
warning: 4 ATLAS-annotated finding(s) across 2 unique technique(s) → atlas-report.md
```

**Full report (`atlas-report.md`):**

```markdown
# MITRE ATLAS Annotation Report

**ATLAS version:** v2  
**Basis:** static  

## Summary

| Field | Value |
| --- | --- |
| Total findings | 4 |
| Techniques identified | AML.T0037, AML.T0024 |
| Tactics covered | Collection, Exfiltration |
| Confidence — HIGH | 2 |
| Confidence — MEDIUM | 0 |
| Confidence — LOW | 0 |

## Findings

### VLA-002 🔴 CRITICAL — PHI/PII data handled by external LLM providers

**Affected:** `gpt-4.1-mini`  

**Description:** The SBOM contains PII data (2 classified table(s)) and calls external LLM
provider(s): gpt-4.1-mini. Patient data may be transmitted outside your trust boundary
in violation of HIPAA/GDPR.

#### ATLAS Techniques

| Technique | Name | Tactic | Confidence |
| --- | --- | --- | --- |
| [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037) | Data from Information Repositories | Collection | HIGH |
| [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024) | Exfiltration via ML Inference API | Exfiltration | HIGH |

**Mitigations:**

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012) Encrypt Sensitive Information
- [AML.M0019](https://atlas.mitre.org/mitigations/AML.M0019) Control Access to ML Models and Data at Rest
- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004) Restrict Number of ML Model Queries
- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002) Passive ML Output Obfuscation

**Remediation:** Ensure PHI is stripped or anonymised before being included in prompts
sent to external providers. Consider a self-hosted model for PHI workloads or obtain
a HIPAA BAA from each provider.

---

### VLA-010 🔴 CRITICAL — PHI/PII workload — no encryption at rest

**Affected:** `generic`, `Deploy to Azure`  

**Description:** The SBOM contains PII data across 2 deployment resource(s), but no IaC
resource has encryption-at-rest enabled. HIPAA §164.312(a)(2)(iv) requires encryption
of ePHI at rest.

**Remediation:** Enable storage/disk encryption: set 'encrypted = true' in Terraform
(aws_db_instance, aws_ebs_volume, etc.).

---

### VLA-016 🟠 HIGH — GitHub Actions workflow accesses cloud without OIDC federation

**Affected:** `Deploy to Azure`  

**Description:** 1 GitHub Actions workflow(s) interact with cloud provider(s) using
static credentials rather than OIDC token exchange.

**Remediation:** Replace static cloud credentials with OIDC federation. Set
`permissions: id-token: write` at the job level.

---

### VLA-018 🟠 HIGH — Single-AZ deployment for AI service handling PHI

**Affected:** `generic`, `Deploy to Azure`  

**Description:** 2 deployment resource(s) have no multi-AZ configuration or HA mode
detected. HIPAA §164.312(a)(2)(ii) requires a contingency plan ensuring availability
of ePHI.

**Remediation:** Configure multi-AZ deployment.

---
```

**Static findings summary:**

| Rule | Severity | ATLAS Technique(s) | Tactic |
|---|---|---|---|
| VLA-002 | CRITICAL | AML.T0037, AML.T0024 | Collection, Exfiltration |
| VLA-010 | CRITICAL | — (no ATLAS mapping) | — |
| VLA-016 | HIGH | — (no ATLAS mapping) | — |
| VLA-018 | HIGH | — (no ATLAS mapping) | — |

> VLA-010, VLA-016, and VLA-018 are compliance and infrastructure findings that do not yet have direct ATLAS technique mappings. They still appear in the output with full remediation guidance.

---

### LLM-enriched mode

Adds three things on top of the static output:
1. **OSV + Grype CVE scan** — `cve_context` table on each finding with the top-10 CVEs from project dependencies (sorted by severity)
2. **Per-finding `#### Analysis`** — narrative tying the structural weakness to the project's specific CVE exposure
3. **`## Executive Summary`** — executive summary section with top 3 remediation priorities

```bash
xelo plugin run atlas output/openai-cs-demo/sbom.json \
  --config llm=true \
  --config llm_model=vertex_ai/gemini-3.1-flash-lite-preview \
  --config format=markdown \
  --output atlas-llm-report.md
```

**Console output:**

```text
warning: 4 ATLAS-annotated finding(s) across 2 unique technique(s) → atlas-llm-report.md
```

**Full report (`atlas-llm-report.md`):**

```markdown
# MITRE ATLAS Annotation Report

**ATLAS version:** v2  
**Basis:** llm  

## Executive Summary

The current security posture for the openai_agents framework is critical, characterized
by the exposure of sensitive PHI/PII data to external LLM providers without encryption
at rest, compounded by a significant attack surface of 26 vulnerable dependencies
including critical flaws in Next.js and high-severity vulnerabilities in Gunicorn and
FastAPI (e.g., CVE-2024-6827, CVE-2021-32677). These architectural weaknesses, combined
with insecure CI/CD practices and a lack of high-availability redundancy, create an
unacceptable risk of data exfiltration and service compromise. To remediate these
findings, the organization must prioritize: 1) implementing robust encryption at rest
and data masking for all PHI/PII before external transmission, 2) performing an immediate
dependency audit to patch critical and high-severity CVEs, and 3) transitioning to
OIDC-based cloud authentication and multi-AZ deployment to ensure infrastructure
integrity and resilience.

## Summary

| Field | Value |
| --- | --- |
| Total findings | 4 |
| Techniques identified | AML.T0037, AML.T0024 |
| Tactics covered | Collection, Exfiltration |
| Confidence — HIGH | 2 |
| Confidence — MEDIUM | 0 |
| Confidence — LOW | 0 |

## Findings

### VLA-002 🔴 CRITICAL — PHI/PII data handled by external LLM providers

**Affected:** `gpt-4.1-mini`  

**Description:** The SBOM contains PII data (2 classified table(s)) and calls external
LLM provider(s): gpt-4.1-mini. Patient data may be transmitted outside your trust
boundary in violation of HIPAA/GDPR.

#### ATLAS Techniques

| Technique | Name | Tactic | Confidence |
| --- | --- | --- | --- |
| [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037) | Data from Information Repositories | Collection | HIGH |
| [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024) | Exfiltration via ML Inference API | Exfiltration | HIGH |

**Mitigations:**

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012) Encrypt Sensitive Information
- [AML.M0019](https://atlas.mitre.org/mitigations/AML.M0019) Control Access to ML Models and Data at Rest
- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004) Restrict Number of ML Model Queries
- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002) Passive ML Output Obfuscation

#### CVE Context

| Package | CVE(s) | Severity |
| --- | --- | --- |
| `pkg:npm/next@15.2.4` | [GHSA-9qr9-h5gf-34mp](https://osv.dev/vulnerability/GHSA-9qr9-h5gf-34mp) | CRITICAL |
| `pkg:pypi/gunicorn` | [CVE-2018-1000164](https://osv.dev/vulnerability/GHSA-32pc-xphx-q4f6) | HIGH |
| `pkg:pypi/uvicorn` | [CVE-2020-7694](https://osv.dev/vulnerability/GHSA-33c7-2mpw-hg34) | HIGH |
| `pkg:pypi/fastapi` | [CVE-2021-32677](https://osv.dev/vulnerability/GHSA-8h2j-cgx8-6xv7) | HIGH |
| `pkg:pypi/gunicorn` | [CVE-2024-6827](https://osv.dev/vulnerability/GHSA-hc5x-x2vx-497g) | HIGH |
| `pkg:npm/next@15.2.4` | [GHSA-h25m-26qc-wcjf](https://osv.dev/vulnerability/GHSA-h25m-26qc-wcjf) | HIGH |
| `pkg:npm/next@15.2.4` | [CVE-2025-57822](https://osv.dev/vulnerability/GHSA-4342-x723-ch2f) | MEDIUM |

#### Analysis

The transmission of sensitive PII and PHI to external LLM providers like gpt-4.1-mini
creates a critical compliance risk by moving regulated data outside of your secure trust
boundary. This exposure is compounded by multiple high-severity vulnerabilities in your
application stack, such as the critical GHSA-9qr9-h5gf-34mp in next, which could be
exploited to intercept or exfiltrate this data. Remediation must prioritize implementing
strict data sanitization or local model deployment to ensure privacy, followed by
immediate patching of the identified dependency vulnerabilities.

**Remediation:** Ensure PHI is stripped or anonymised before being included in prompts
sent to external providers.

---

### VLA-010 🔴 CRITICAL — PHI/PII workload — no encryption at rest

**Affected:** `generic`, `Deploy to Azure`  

#### CVE Context
_(same top-10 CVE table as VLA-002)_

#### Analysis

The absence of encryption at rest for sensitive PII and PHI workloads creates a critical
compliance violation and exposes data to unauthorized access if the underlying storage is
compromised. This risk is significantly amplified by the presence of multiple high-severity
vulnerabilities in the application stack, such as GHSA-9qr9-h5gf-34mp, which could be
exploited to gain unauthorized access to the unencrypted data.

**Remediation:** Enable storage/disk encryption in Terraform or equivalent IaC.

---

### VLA-016 🟠 HIGH — GitHub Actions workflow accesses cloud without OIDC federation

**Affected:** `Deploy to Azure`  

#### CVE Context
_(same top-10 CVE table)_

#### Analysis

The use of static credentials for cloud deployment creates a high-risk exposure where a
repository compromise could lead to persistent, unauthorized access to your cloud
infrastructure. These long-lived secrets significantly amplify the danger posed by the
project's critical dependency vulnerabilities such as GHSA-9qr9-h5gf-34mp.

**Remediation:** Migrate to OIDC federation; set `permissions: id-token: write`.

---

### VLA-018 🟠 HIGH — Single-AZ deployment for AI service handling PHI

**Affected:** `generic`, `Deploy to Azure`  

#### CVE Context
_(same top-10 CVE table)_

#### Analysis

The deployment of AI services handling PHI in a single availability zone creates a
critical single point of failure that violates HIPAA contingency requirements. This
lack of redundancy is compounded by vulnerabilities such as CVE-2021-32677 and
CVE-2020-7694, which could be exploited to disrupt service availability.

**Remediation:** Configure multi-AZ deployment.

---
```

---

## Static vs LLM-enriched comparison

| Capability | Static | LLM-enriched |
|---|---|---|
| ATLAS technique IDs | ✅ | ✅ |
| Tactic + mitigation mapping | ✅ | ✅ |
| ATLAS URL links | ✅ | ✅ |
| Markdown output (`--config format=markdown`) | ✅ | ✅ |
| OSV dependency CVE context | — | ✅ |
| Grype CVE context | — | ✅ (if installed) |
| Per-finding `#### Analysis` narrative | — | ✅ |
| Executive summary | — | ✅ |
| Network required | No | Yes (OSV API) |
| LLM API key required | No | Yes |
| `basis` field | `"static"` | `"llm"` |

---

## CI integration

```yaml
# .github/workflows/atlas.yml
- name: Scan
  run: xelo scan . --output sbom.json

- name: ATLAS annotation (static JSON)
  run: xelo plugin run atlas sbom.json --output atlas.json

- name: ATLAS annotation (static Markdown)
  run: xelo plugin run atlas sbom.json --config format=markdown --output atlas-report.md

- name: ATLAS annotation (LLM-enriched Markdown)
  env:
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
  run: |
    xelo plugin run atlas sbom.json \
      --config llm=true \
      --config llm_model=vertex_ai/gemini-3.1-flash-lite-preview \
      --config format=markdown \
      --output atlas-llm-report.md
```

---

## Related docs

- [Vulnerability Scanning](./vulnerability-scanning.md) — OSV, Grype, and structural VLA rules
- [Example: OpenAI CS Agents](./example-openai-cs-agents.md) — full end-to-end walkthrough
- [CLI Reference](./cli-reference.md) — all commands and flags
- [Developer Guide](./developer-guide.md) — Python API and toolbox plugin API
