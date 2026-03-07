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

Validate a produced SBOM against the bundled schema:

```bash
xelo validate sbom.json
# OK — document is valid
```

Print or save the JSON Schema:

```bash
xelo schema                            # print to stdout
xelo schema --output aibom.schema.json # write to file
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

Xelo ships with built-in analysis plugins invoked via `xelo plugin run`:

```bash
xelo plugin list                                          # list all plugins

xelo plugin run vulnerability sbom.json                   # offline VLA rules
xelo plugin run atlas sbom.json --output atlas.json       # MITRE ATLAS annotation
xelo plugin run sarif sbom.json --output results.sarif    # SARIF 2.1.0
xelo plugin run markdown sbom.json --output report.md     # Markdown report
xelo plugin run cyclonedx sbom.json --output bom.cdx.json # CycloneDX 1.6

# Policy assessment (LLM required)
xelo plugin run policy sbom.json \
  --config policy_file=owasp_ai_top10.json \
  --config llm_model=gpt-4o \
  --output policy-report.json
```

| Plugin | CLI name | Network | What it does |
| --- | --- | --- | --- |
| `VulnerabilityScannerPlugin` | `vulnerability` | No | Structural VLA rules — missing guardrails, unprotected models, over-privileged agents |
| `AtlasAnnotatorPlugin` | `atlas` | No | Maps every finding to MITRE ATLAS v2 techniques and mitigations |
| `PolicyAssessmentPlugin` | `policy` | No* | Evaluates the AI SBOM against a custom policy file (OWASP AI Top 10, HIPAA, …) |
| `LicenseCheckerPlugin` | `license` | No | Checks dependency licence compliance |
| `DependencyAnalyzerPlugin` | `dependency` | No | Scores dependency freshness and flags outdated AI packages |
| `SarifExporterPlugin` | `sarif` | No | Exports findings as SARIF 2.1.0 (GitHub Code Scanning / GHAS compatible) |
| `CycloneDxExporter` | `cyclonedx` | No | Exports nodes as CycloneDX 1.6 |
| `MarkdownExporterPlugin` | `markdown` | No | Human-readable Markdown report |
| `GhasUploaderPlugin` | `ghas` | Yes | Uploads SARIF to GitHub Advanced Security |
| `AwsSecurityHubPlugin` | `aws-security-hub` | Yes | Pushes findings to AWS Security Hub (requires `boto3`) |
| `XrayPlugin` | `xray` | Yes | Pushes findings to JFrog Xray |

Plugins are also importable as a Python library:

```python
import json
from xelo import AiSbomExtractor, AiSbomConfig
from xelo.toolbox.plugins.vulnerability import VulnerabilityScannerPlugin
from xelo.toolbox.plugins.atlas_annotator import AtlasAnnotatorPlugin
from xelo.toolbox.plugins.sarif_exporter import SarifExporterPlugin
from xelo.toolbox.plugins.markdown_exporter import MarkdownExporterPlugin

doc = AiSbomExtractor().extract_from_path("./my-repo", config=AiSbomConfig())
sbom = doc.model_dump(mode="json")

vuln = VulnerabilityScannerPlugin().run(sbom, {})
print(vuln.status, vuln.message)

atlas = AtlasAnnotatorPlugin().run(sbom, {})
for finding in atlas.details["findings"]:
    print(finding["rule_id"], finding["severity"], finding["atlas"]["techniques"])

sarif = SarifExporterPlugin().run(sbom, {})
open("results.sarif", "w").write(json.dumps(sarif.details, indent=2))

md = MarkdownExporterPlugin().run(sbom, {})
open("report.md", "w").write(md.details["markdown"])
```

To add **custom detection adapters** (extending framework coverage), subclass `xelo.plugins.PluginAdapter` and register under the `xelo.plugins` entry-point group. Enable at scan time with `AiSbomExtractor(load_plugins=True)`. See the [Developer Guide](./docs/developer-guide.md) for details.

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
