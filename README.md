# Xelo

Xelo is an open-source AI SBOM (Software Bill of Materials) generator for agentic and LLM-powered applications. It scans source code and configuration, produces a structured AI-BOM document, and supports CycloneDX export for security and compliance workflows.

## What Xelo Does

Xelo analyses a repository and produces an [AI SBOM](./docs/aibom-schema.md) — a machine-readable inventory of every AI component it can find:

- **Agents** — agentic orchestrators (LangGraph graphs, CrewAI crews, AutoGen agents, OpenAI Agents, …)
- **Models** — LLM and embedding model references, including provider and version
- **Tools** — function tools and MCP tools wired to agents
- **Prompts** — system instructions and prompt templates (full content preserved)
- **Datastores** — vector stores, databases, caches; with PII/PHI data-classification from SQL and Python models
- **Guardrails** — content filters and safety validators
- **Auth** — authentication nodes (OAuth2, API key, Bearer, JWT, MCP auth providers)
- **Privileges** — capability grants (db_write, filesystem_write, code_execution, …)
- **Deployment** — Docker image references, cloud targets, IaC context

Xelo runs a **3-phase pipeline**: AST-aware adapters → regex fallbacks → optional LLM enrichment. The first two phases are fully deterministic and require no API key.

## Supported Frameworks

**Python:** LangChain, LangGraph, OpenAI Agents SDK, CrewAI (code + YAML), AutoGen (code + YAML), Google ADK, LlamaIndex, Agno, AWS BedrockAgentCore, Azure AI Agent Service, Guardrails AI, MCP Server (FastMCP / low-level), Semantic Kernel

**TypeScript / JavaScript:** LangChain.js, LangGraph.js, OpenAI Agents (TS), Azure AI Agents (TS), Agno (TS), MCP Server (TS)

## Installation

```bash
pip install xelo
```

Install for development (all extras):

```bash
pip install -e ".[dev]"
```

## Quickstart

Scan a local repository:

```bash
xelo scan ./my-repo --output sbom.json
```

Scan a remote repository:

```bash
xelo scan https://github.com/org/repo --ref main --output sbom.json
```

Add LLM enrichment for richer output (recommended for production use):

```bash
export OPENAI_API_KEY=sk-...
xelo scan ./my-repo --llm --llm-model gpt-4o-mini --output sbom.json
```

CLI alias: `ai-sbom`. Run `xelo --help` for all flags.

## Output Formats

| Flag | Format |
| --- | --- |
| `--format json` (default) | Xelo-native AI SBOM (see [schema docs](./docs/aibom-schema.md)) |
| `--format cyclonedx` | CycloneDX 1.6 JSON (AI components only) |
| `--format unified` | CycloneDX merged with standard dependency SBOM |

Validate a produced document:

```bash
xelo validate sbom.json
```

Print the JSON schema:

```bash
xelo schema
```

## Toolbox Plugins

Xelo ships with built-in analysis plugins in `xelo.toolbox.plugins`:

| Plugin | What it does |
| --- | --- |
| `VulnerabilityScannerPlugin` | Structural VLA rules — flags missing guardrails, unprotected models, over-privileged agents |
| `AtlasAnnotatorPlugin` | Maps every finding to MITRE ATLAS v2 techniques and mitigations |
| `PolicyAssessmentPlugin` | Evaluates the AI SBOM against a custom policy file (OWASP AI Top 10, HIPAA, …) |
| `LicenseCheckerPlugin` | Checks dependency licence compliance |
| `DependencyAnalyzerPlugin` | Scores dependency freshness and flags outdated AI packages |
| `SarifExporterPlugin` | Exports findings as SARIF 2.1.0 (GitHub Code Scanning / GHAS compatible) |
| `CycloneDxExporter` | Exports as CycloneDX |
| `MarkdownExporterPlugin` | Human-readable Markdown report |
| `GhasUploaderPlugin` | Uploads SARIF to GitHub Advanced Security |
| `AwsSecurityHubPlugin` | Pushes findings to AWS Security Hub (requires `boto3`) |
| `XrayPlugin` | Pushes findings to JFrog Xray |

```python
from xelo import AiSbomExtractor, AiSbomConfig
from xelo.toolbox.plugins.vulnerability import VulnerabilityScannerPlugin
from xelo.toolbox.plugins.atlas_annotator import AtlasAnnotatorPlugin

doc = AiSbomExtractor().extract_from_path("./my-repo", config=AiSbomConfig())
sbom = doc.model_dump(mode="json")

result = VulnerabilityScannerPlugin().run(sbom, {})
print(result.status, result.message)

atlas = AtlasAnnotatorPlugin().run(sbom, {})
for finding in atlas.details["findings"]:
    print(finding["rule_id"], finding["severity"], finding["atlas"]["techniques"])
```

## Configuration

CLI flags take precedence over environment variables.

| Variable | Purpose | Default |
| --- | --- | --- |
| `XELO_LLM` | Enable LLM enrichment (`true`/`1`) | `false` |
| `XELO_LLM_MODEL` | LLM model passed to litellm | `gpt-4o-mini` |
| `XELO_LLM_API_KEY` | API key (or use provider-native env vars) | — |
| `XELO_LLM_API_BASE` | Base URL for self-hosted / proxy endpoints | — |
| `XELO_LLM_BUDGET_TOKENS` | Max tokens for enrichment | `50000` |

Legacy `AISBOM_*` names are accepted as fallbacks.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests   # lint
mypy src               # type-check
pytest                 # all tests
pytest -m "not smoke"  # skip network-dependent tests
```

Run the benchmark evaluation suite against cached fixtures:

```bash
python -m tests.test_toolbox.evaluate --all --mode local --verbose
```

## Documentation

- [Getting Started](./docs/getting-started.md)
- [AI SBOM Schema](./docs/aibom-schema.md)
- [CLI Reference](./docs/cli-reference.md)
- [Developer Guide](./docs/developer-guide.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Contributing](./CONTRIBUTING.md)
- [Roadmap](./ROADMAP.md)

## License

Apache-2.0. See [LICENSE](./LICENSE).
