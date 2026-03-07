<img src="xelo-logo.png" alt="Xelo" height="20" />

# Getting Started

This guide gets you from install to your first AI SBOM in a few commands.

## Prerequisites

- Python `3.11` or newer
- Optional: `git` on `PATH` (required for scanning remote repositories)
- Optional: an LLM API key for enriched output (OpenAI, Anthropic, Gemini, Bedrock, etc.)

## Install

```bash
pip install xelo
```

## Your First Scan

Run a local scan and write the AI SBOM to a file:

```bash
xelo scan ./my-repo --output sbom.json
```

Scan a remote GitHub repository directly:

```bash
xelo scan https://github.com/org/repo --ref main --output sbom.json
```

A successful scan prints:

```text
14 nodes, 18 edges → sbom.json
```

Run `xelo validate sbom.json` to confirm the output is valid.

## Understanding the Output

The JSON document contains five top-level fields:

```json
{
  "schema_version": "1.1.0",
  "generated_at": "2026-03-07T08:00:00Z",
  "target": "./my-repo",
  "nodes": [...],
  "edges": [...],
  "deps":  [...],
  "summary": {...}
}
```

- **`nodes`** — every detected AI component. Each node has a `component_type` (AGENT, MODEL, TOOL, PROMPT, DATASTORE, GUARDRAIL, AUTH, PRIVILEGE, DEPLOYMENT, FRAMEWORK, API_ENDPOINT), a `name`, a `confidence` score, and a `metadata` object with typed fields like `model_name`, `datastore_type`, `privilege_scope`, `transport`, etc.
- **`edges`** — directed relationships between nodes (USES, CALLS, ACCESSES, PROTECTS, DEPLOYS). Use these to understand which agents call which tools and models.
- **`deps`** — package dependencies scanned from `requirements.txt`, `pyproject.toml`, and `package.json` files at any depth.
- **`summary`** — scan-level roll-up: detected frameworks, I/O modalities, API endpoints, deployment platforms, data classification labels, and a natural-language use-case description.

For a full description of every field, see [AI SBOM Schema](./aibom-schema.md).

## LLM Enrichment — Why and When to Use It

By default Xelo uses only AST parsing and regex patterns. This is fast, deterministic, and requires no API key. It catches the vast majority of components for known frameworks.

**Enable LLM enrichment when you need:**

1. **A better use-case summary.** Without LLM, the `summary.use_case` field is a rule-based sentence assembled from component counts. With LLM it becomes a concise natural-language description of what the application actually does — useful in security reviews, compliance reports, and vendor assessments.

2. **Node descriptions for MCP servers.** Xelo can describe each MCP server it finds (tools offered, transport, auth type) in a single readable sentence — something regex cannot produce without seeing the full context.

3. **Higher confidence on ambiguous detections.** The LLM verification pass re-evaluates nodes that the AST/regex phases marked as uncertain. This can promote borderline detections and suppress false positives in complex codebases.

4. **Richer output for downstream consumers.** Tools like the vulnerability scanner and ATLAS annotator produce better results when node metadata is more complete. LLM enrichment fills gaps (e.g. model family, provider context) that affect which VLA rules fire.

**Cost is controlled.** Token usage is capped by `XELO_LLM_BUDGET_TOKENS` (default 50 000). A typical medium-size repo uses 5 000–15 000 tokens — a few cents with GPT-4o-mini or free with Gemini Flash.

### Enabling LLM Enrichment

Via CLI:

```bash
export OPENAI_API_KEY=sk-...
xelo scan ./my-repo --llm --llm-model gpt-4o-mini --output sbom.json
```

Via environment variables:

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=gpt-4o-mini
export OPENAI_API_KEY=sk-...
xelo scan ./my-repo --output sbom.json
```

Other providers work through [litellm](https://docs.litellm.ai/docs/providers) — just change `--llm-model`:

| Provider | Model string |
| --- | --- |
| OpenAI | `gpt-4o-mini`, `gpt-4o` |
| Anthropic | `anthropic/claude-3-5-sonnet-latest` |
| Google Gemini | `gemini/gemini-2.0-flash` |
| AWS Bedrock | `bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0` |
| Azure OpenAI | `azure/gpt-4o-mini` + `XELO_LLM_API_BASE` |
| Any OpenAI-compatible | `openai/<model>` + `XELO_LLM_API_BASE` |

## Output Formats

```bash
# Default: Xelo-native AI SBOM JSON
xelo scan ./my-repo --output sbom.json

# CycloneDX 1.6 (AI components only)
xelo scan ./my-repo --format cyclonedx --output sbom.cdx.json

# Unified: AI SBOM merged with standard dependency BOM
xelo scan ./my-repo --format unified --output sbom.unified.json
```

## Validating and Inspecting the Schema

After scanning, confirm the output is structurally valid:

```bash
xelo validate sbom.json
# OK — document is valid
```

Print the full JSON Schema to stdout (useful for editor integration or CI linting):

```bash
xelo schema
```

Write it to a file:

```bash
xelo schema --output aibom.schema.json
```

## Running Toolbox Plugins

Toolbox plugins analyse an existing SBOM and produce findings, reports, and exports. Run them with `xelo plugin run`:

```bash
# See all available plugins
xelo plugin list

# Structural vulnerability / VLA rules
xelo plugin run vulnerability sbom.json

# Write findings to a JSON file
xelo plugin run vulnerability sbom.json --output findings.json

# MITRE ATLAS annotation
xelo plugin run atlas sbom.json --output atlas.json

# SARIF export for GitHub Code Scanning
xelo plugin run sarif sbom.json --output results.sarif

# Human-readable Markdown report
xelo plugin run markdown sbom.json --output report.md

# CycloneDX export
xelo plugin run cyclonedx sbom.json --output bom.cdx.json

# Policy assessment (requires LLM)
xelo plugin run policy sbom.json \
  --config policy_file=owasp_ai_top10.json \
  --config llm_model=gpt-4o \
  --config repo_path=./my-repo \
  --output policy-report.json
```

Each plugin writes its output to `--output` (default: stdout). When `--output` is a file, xelo prints a one-line summary (`ok: ... → file.json`) to stdout.

For the full list of plugins, config options, and integration targets (GHAS, AWS Security Hub, JFrog Xray) see the [CLI Reference — Toolbox Plugins](./cli-reference.md) and [Developer Guide](./developer-guide.md).

## Supported Frameworks

Xelo detects components from the following frameworks without any additional config:

**Python:** LangChain, LangGraph, OpenAI Agents SDK, CrewAI (code + YAML configs), AutoGen (code + YAML configs), Google ADK, LlamaIndex, Agno, AWS BedrockAgentCore, Azure AI Agent Service, Guardrails AI, MCP Server (FastMCP / low-level), Semantic Kernel

**TypeScript / JavaScript:** LangChain.js, LangGraph.js, OpenAI Agents (TS), Azure AI Agents (TS), Agno (TS), MCP Server (TS)

## Next Steps

- Full command and flag reference: [CLI Reference](./cli-reference.md)
- Understand every field in the output: [AI SBOM Schema](./aibom-schema.md)
- Use Xelo as a Python library or run toolbox plugins: [Developer Guide](./developer-guide.md)
- Something not working: [Troubleshooting](./troubleshooting.md)
