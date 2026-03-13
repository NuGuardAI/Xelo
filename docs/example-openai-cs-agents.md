# Example: OpenAI Customer-Service Agents Demo

**Repository**: [NuGuardAI/openai-cs-agents-demo](https://github.com/NuGuardAI/openai-cs-agents-demo)  
**Framework**: OpenAI Agents SDK  
**Mode**: Fully offline — no LLM key required  
**Xelo version**: 0.2.0+

This walkthrough scans a public OpenAI customer-service demo application end-to-end and produces four security artefacts (all without any llm):

| # | Output | Command |
|---|---|---|
| a | Unified CycloneDX BOM (AI + standard deps) | `xelo scan … --format unified` |
| b | Human-readable Markdown report | `xelo plugin run markdown` |
| c | Dependency CVE advisories | `xelo plugin run vulnerability --config provider=osv` |
| d | Structural VLA rule findings | `xelo plugin run vulnerability --config provider=structural` |

---

## About the example application

The repo contains a multi-agent airline customer-service chatbot built with the OpenAI Agents SDK. It includes:

- 5 specialised agents (Triage, FAQ, Flight Status, Seat Booking, Cancellation)
- Per-agent system-prompt instructions
- 6 function tools wired to each agent
- 2 guardrails (jailbreak filter, relevance filter)
- A Next.js front-end and FastAPI backend
- Azure deployment workflow via GitHub Actions

---

## Prerequisites

```bash
pip install "xelo[toolbox]"
```

No LLM API key is needed. All commands below run fully offline (dependency CVE checks query the public OSV API over HTTPS — skip those with `--config provider=structural` for air-gapped environments).

---

## Step 1 — Scan the repository

```bash
xelo scan https://github.com/NuGuardAI/openai-cs-agents-demo \
  --ref main \
  --output sbom.json
```

**Console output:**

```text
29 nodes, 36 edges → sbom.json
```

Xelo detected:

| Component type | Count |
|---|---|
| AGENT | 5 |
| TOOL | 6 |
| PROMPT | 8 |
| GUARDRAIL | 2 |
| MODEL | 1 |
| DEPLOYMENT | 2 |
| IAM | 1 |
| API_ENDPOINT | 1 |
| AUTH | 1 |
| PRIVILEGE | 1 |
| FRAMEWORK | 1 |

**Scan summary highlights:**

- Framework: `openai_agents`
- Model: `gpt-4.1-mini` (external OpenAI provider)
- Data classification: **PII** — tables `AirlineAgentContext`, `GuardrailCheck`
- Deployment targets: Azure, GitHub Actions
- Encryption at rest: **not configured**
- Secret store: `github_actions_secret`

Validate the SBOM against the bundled schema:

```bash
xelo validate sbom.json
# OK — document is valid
```

---

## Output (a) — Unified CycloneDX JSON

The `unified` format generates a single CycloneDX 1.6 BOM that contains **both standard package dependencies and AI component metadata** merged into one document.

```bash
xelo scan https://github.com/NuGuardAI/openai-cs-agents-demo \
  --ref main \
  --format unified \
  --output sbom-unified.cdx.json
```

**Console output:**

```text
29 nodes, 36 edges → sbom-unified.cdx.json
```

**Abbreviated output structure** (`sbom-unified.cdx.json`):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:1.3.0-20260313T041911Z",
  "metadata": {
    "timestamp": "2026-03-13T04:19:11Z",
    "tools": [
      { "vendor": "Xelo", "name": "xelo", "version": "0.2.0" }
    ],
    "properties": [
      { "name": "aibom:scanTarget",       "value": "https://github.com/NuGuardAI/openai-cs-agents-demo" },
      { "name": "aibom:aiComponentTotal", "value": "29" },
      { "name": "aibom:aiRelationships",  "value": "36" },
      { "name": "aibom:count:agent",      "value": "5" },
      { "name": "aibom:count:tool",       "value": "6" },
      { "name": "aibom:count:prompt",     "value": "8" },
      { "name": "aibom:count:guardrail",  "value": "2" },
      { "name": "aibom:count:model",      "value": "1" },
      { "name": "aibom:avgConfidence",    "value": "0.85" },
      { "name": "aibom:qualityGate",      "value": "pass" }
    ]
  },
  "components": [
    {
      "bom-ref": "pkg:pypi/pydantic",
      "type": "library",
      "name": "pydantic",
      "purl": "pkg:pypi/pydantic",
      "properties": [
        { "name": "xelo:dep_group",    "value": "runtime" },
        { "name": "xelo:source_file",  "value": "pyproject.toml" },
        { "name": "xelo:version_spec", "value": ">=2.7.0,<3" }
      ]
    },
    {
      "bom-ref": "pkg:npm/next@15.2.4",
      "type": "library",
      "name": "next",
      "version": "15.2.4",
      "purl": "pkg:npm/next@15.2.4",
      "properties": [
        { "name": "xelo:dep_group",   "value": "runtime" },
        { "name": "xelo:source_file", "value": "package.json" }
      ]
    }
  ],
  "services": [
    {
      "bom-ref": "ai:agent:triage_agent",
      "name": "Triage Agent",
      "data": [
        { "flow": "inbound",  "classification": "PII" },
        { "flow": "outbound", "classification": "PII" }
      ],
      "properties": [
        { "name": "aibom:component_type", "value": "AGENT" },
        { "name": "aibom:confidence",     "value": "0.92" },
        { "name": "aibom:framework",      "value": "openai_agents" }
      ]
    }
  ]
}
```

> The full document contains 28 package components (Python + npm) and all 29 AI component entries as CycloneDX `services` with `aibom:*` properties.

---

## Output (b) — Markdown Report

```bash
xelo plugin run markdown sbom.json --output report.md
```

**Console output:**

```text
ok: Markdown report generated (29 node(s), 28 dep(s)) → report.md
```

**Full report content** (`report.md`):

```markdown
# SBOM Report: https://github.com/NuGuardAI/openai-cs-agents-demo

**Generated:** 2026-03-13T04:19:03Z
**Schema version:** 1.3.0

## Summary

| Field | Value |
| --- | --- |
| AI nodes | 29 |
| Dependencies | 28 |
| Data classification | PII |
| Classified tables | AirlineAgentContext, GuardrailCheck |
| Use case | Agentic AI workflow with 5 agent(s), 6 tool integration(s), and 2 guardrail control(s). Detected use cases include FAQ question answering, request triage and routing. |
| Frameworks | openai_agents |
| Modalities | TEXT |

## AI Components

| Name | Type | Confidence |
| --- | --- | --- |
| Cancellation Agent | AGENT | 92% |
| FAQ Agent | AGENT | 92% |
| Flight Status Agent | AGENT | 92% |
| Seat Booking Agent | AGENT | 92% |
| Triage Agent | AGENT | 92% |
| generic | API_ENDPOINT | 55% |
| generic | AUTH | 58% |
| generic | DEPLOYMENT | 70% |
| Deploy to Azure | DEPLOYMENT | 95% |
| framework:openai_agents | FRAMEWORK | 95% |
| Jailbreak Guardrail | GUARDRAIL | 92% |
| Relevance Guardrail | GUARDRAIL | 92% |
| ${{ secrets.AZURE_CREDENTIALS }} | IAM | 93% |
| gpt-4.1-mini | MODEL | 90% |
| db_write | PRIVILEGE | 55% |
| Cancellation Agent Instructions | PROMPT | 92% |
| FAQ Agent Instructions | PROMPT | 92% |
| Flight Status Agent Instructions | PROMPT | 92% |
| Jailbreak Guardrail Instructions | PROMPT | 92% |
| Relevance Guardrail Instructions | PROMPT | 92% |
| Seat Booking Agent Instructions | PROMPT | 92% |
| Triage Agent Instructions | PROMPT | 92% |
| generic | PROMPT | 55% |
| baggage_tool | TOOL | 85% |
| cancel_flight | TOOL | 85% |
| display_seat_map | TOOL | 85% |
| faq_lookup_tool | TOOL | 85% |
| flight_status_tool | TOOL | 85% |
| update_seat | TOOL | 85% |

## Dependencies

| Name | Version | Group | License |
| --- | --- | --- | --- |
| openai-agents |  | runtime | |
| pydantic |  | runtime | |
| fastapi |  | runtime | |
| uvicorn |  | runtime | |
| gunicorn |  | runtime | |
| python-dotenv |  | runtime | |
| next | ^15.2.4 | runtime | |
| react | ^19.0.0 | runtime | |
| openai | ^4.87.3 | runtime | |
| … (28 total) | | | |

## Node Type Breakdown

| Type | Count |
| --- | --- |
| AGENT | 5 |
| API_ENDPOINT | 1 |
| AUTH | 1 |
| DEPLOYMENT | 2 |
| FRAMEWORK | 1 |
| GUARDRAIL | 2 |
| IAM | 1 |
| MODEL | 1 |
| PRIVILEGE | 1 |
| PROMPT | 8 |
| TOOL | 6 |
```

---

## Output (c) — Dependency CVE Advisories

Runs OSV.dev advisory lookup against all discovered package dependencies — no LLM or Grype binary needed.

```bash
xelo plugin run vulnerability sbom.json \
  --config provider=osv \
  --output vuln-cve.json
```

**Console output:**

```text
failed: Found 30 finding(s): 3 CRITICAL, 10 HIGH, 12 MEDIUM, 5 UNKNOWN → vuln-cve.json
```

> `status: failed` means confirmed CVEs at HIGH or CRITICAL severity were found. See the [Vulnerability Scanning reference](./vulnerability-scanning.md) for `status` semantics.

**Key CVE findings** (abbreviated from `vuln-cve.json`):

| Severity | Advisory | Package | CVE | Title |
|---|---|---|---|---|
| CRITICAL | GHSA-9qr9-h5gf-34mp | `next ^15.2.4` | — | Next.js RCE via React flight protocol |
| HIGH | GHSA-hc5x-x2vx-497g | `gunicorn` | CVE-2024-6827 | HTTP Request/Response Smuggling |
| HIGH | GHSA-w3h3-4rj7-4ph4 | `gunicorn` | CVE-2024-1135 | Request smuggling / endpoint bypass |
| HIGH | GHSA-33c7-2mpw-hg34 | `uvicorn` | CVE-2020-7694 | Log injection |
| HIGH | GHSA-f97h-2pfx-f59f | `uvicorn` | CVE-2020-7695 | HTTP response splitting |
| HIGH | GHSA-8h2j-cgx8-6xv7 | `fastapi` | CVE-2021-32677 | CSRF vulnerability |
| HIGH | GHSA-h25m-26qc-wcjf | `next ^15.2.4` | — | DoS via insecure React Server Components |
| HIGH | GHSA-mwv6-3258-q52c | `next ^15.2.4` | — | Denial of Service with Server Components |
| MEDIUM | GHSA-4342-x723-ch2f | `next ^15.2.4` | CVE-2025-57822 | SSRF via Middleware Redirect Handling |
| MEDIUM | GHSA-mr82-8j83-vxmv | `pydantic` | CVE-2024-3772 | RegExp Denial of Service |
| MEDIUM | GHSA-5jqp-qgf6-3pvh | `pydantic` | CVE-2021-29510 | Infinite loop via `infinity` input |
| MEDIUM | GHSA-7fh5-64p2-3v2j | `postcss ^8` | CVE-2023-44270 | Line return parsing error |

**Finding summary:**

```json
{
  "summary": {
    "total": 30,
    "structural": 0,
    "dep_advisories": 30,
    "critical": 3,
    "high": 10,
    "medium": 12,
    "low": 0
  }
}
```

**Remediation priority:** Upgrade `next` past `15.2.6` (CRITICAL RCE), `gunicorn` to `>=22.0.0`, `uvicorn` to `>=0.11.7`, and `fastapi` to `>=0.65.2`.

---

## Output (d) — Structural VLA Rules

Runs 21 AI-native structural rules against the SBOM graph — **fully offline, no network access, no CVE feed**.

```bash
xelo plugin run vulnerability sbom.json \
  --config provider=structural \
  --output vuln-structural.json
```

**Console output:**

```text
warning: Found 4 finding(s): 2 CRITICAL, 2 HIGH → vuln-structural.json
```

**Full findings** (`vuln-structural.json`):

```json
{
  "status": "warning",
  "tool": "vuln_scan",
  "message": "Found 4 finding(s): 2 CRITICAL, 2 HIGH",
  "details": {
    "provider": "structural",
    "findings": [
      {
        "rule_id": "VLA-002",
        "severity": "CRITICAL",
        "title": "PHI/PII data handled by external LLM providers",
        "description": "The SBOM contains PII data (2 classified table(s)) and calls external LLM provider(s): gpt-4.1-mini. Data may be transmitted outside your trust boundary in violation of HIPAA/GDPR.",
        "affected": ["gpt-4.1-mini"],
        "remediation": "Ensure PII is stripped or anonymised before inclusion in prompts sent to external providers. Consider a self-hosted model for PII workloads or obtain a HIPAA BAA from each provider."
      },
      {
        "rule_id": "VLA-010",
        "severity": "CRITICAL",
        "title": "PHI/PII workload — no encryption at rest",
        "description": "The SBOM contains PII data across 2 deployment resource(s), but no IaC resource has encryption-at-rest enabled. HIPAA §164.312(a)(2)(iv) requires encryption of ePHI at rest.",
        "affected": ["generic", "Deploy to Azure"],
        "remediation": "Enable storage/disk encryption in Terraform ('encrypted = true'), Azure Disk CMEK, or equivalent IaC controls."
      },
      {
        "rule_id": "VLA-016",
        "severity": "HIGH",
        "title": "GitHub Actions workflow accesses cloud without OIDC federation",
        "description": "1 GitHub Actions workflow(s) interact with cloud provider(s) using static credentials rather than OIDC token exchange. Long-lived secrets cannot be automatically rotated.",
        "affected": ["Deploy to Azure"],
        "remediation": "Replace static cloud credentials with OIDC federation using 'azure/login' with federated identity. Set 'permissions: id-token: write' at the job level."
      },
      {
        "rule_id": "VLA-018",
        "severity": "HIGH",
        "title": "Single-AZ deployment for AI service handling PHI",
        "description": "2 deployment resource(s) have no multi-AZ configuration or HA mode detected. HIPAA §164.312(a)(2)(ii) requires a contingency plan ensuring availability of ePHI.",
        "affected": ["generic", "Deploy to Azure"],
        "remediation": "Configure multi-AZ via 'availability_zones' in Terraform, K8s 'topologySpreadConstraints', or equivalent IaC controls."
      }
    ],
    "osv_ran": false,
    "grype_ran": false,
    "summary": {
      "total": 4,
      "structural": 4,
      "dep_advisories": 0,
      "critical": 2,
      "high": 2,
      "medium": 0,
      "low": 0
    }
  }
}
```

**Findings summary:**

| Rule | Severity | Title | Affected |
|---|---|---|---|
| VLA-002 | CRITICAL | PII to external LLM provider | `gpt-4.1-mini` |
| VLA-010 | CRITICAL | No encryption at rest | Azure deployment, generic |
| VLA-016 | HIGH | GitHub Actions without OIDC | `Deploy to Azure` workflow |
| VLA-018 | HIGH | Single-AZ deployment with PII | Azure deployment, generic |

Rules fired here are derived from **OWASP AI Top 10**, **NIST AI RMF**, and **HIPAA**. See the [Structural rule catalogue](./vulnerability-scanning.md) for all 21 rules, conditions, and remediation guidance.

---

## All-in-one command

Run the scan and all four outputs in sequence:

```bash
# 1. AI SBOM (Xelo-native JSON)
xelo scan https://github.com/NuGuardAI/openai-cs-agents-demo \
  --ref main \
  --output sbom.json

# 2a. Unified CycloneDX BOM
xelo scan https://github.com/NuGuardAI/openai-cs-agents-demo \
  --ref main \
  --format unified \
  --output sbom-unified.cdx.json

# 2b. Markdown report
xelo plugin run markdown sbom.json --output report.md

# 2c. Dependency CVE advisories (requires internet for OSV API)
xelo plugin run vulnerability sbom.json \
  --config provider=osv \
  --output vuln-cve.json

# 2d. Structural VLA rules (fully offline)
xelo plugin run vulnerability sbom.json \
  --config provider=structural \
  --output vuln-structural.json
```

Or scan once and run all checks in a single pipeline using `--plugin`:

```bash
xelo scan https://github.com/NuGuardAI/openai-cs-agents-demo \
  --ref main \
  --format unified \
  --output sbom-unified.cdx.json \
  --plugin markdown \
  --plugin-output report.md
```

---

## CI integration example

```yaml
# .github/workflows/ai-sbom.yml
name: AI SBOM
on: [push, pull_request]

jobs:
  xelo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install "xelo[toolbox]"

      - name: Scan
        run: |
          xelo scan . --output sbom.json
          xelo scan . --format unified --output sbom-unified.cdx.json

      - name: Markdown report
        run: xelo plugin run markdown sbom.json --output report.md

      - name: Dependency CVE check
        run: |
          xelo plugin run vulnerability sbom.json \
            --config provider=osv \
            --output vuln-cve.json

      - name: Structural rules (offline gate)
        run: |
          xelo plugin run vulnerability sbom.json \
            --config provider=structural \
            --output vuln-structural.json
          python3 -c "
          import json, sys
          d = json.load(open('vuln-structural.json'))
          s = d['details']['summary']
          sys.exit(1 if s['critical'] > 0 else 0)
          "

      - name: Upload artefacts
        uses: actions/upload-artifact@v4
        with:
          name: ai-sbom
          path: |
            sbom.json
            sbom-unified.cdx.json
            report.md
            vuln-cve.json
            vuln-structural.json
```

---

## Related documentation

- [Getting Started](./getting-started.md) — install, first scan, output fields
- [CLI Reference](./cli-reference.md) — all flags and plugin options
- [Vulnerability Scanning](./vulnerability-scanning.md) — structural rule catalogue, OSV/Grype integration
- [AI SBOM Schema](./aibom-schema.md) — full field reference for the JSON output
