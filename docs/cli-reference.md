# CLI Reference

Xelo CLI command entry points:

- Primary: `xelo`
- Alias: `ai-sbom`

## Command Map

| Command | Purpose |
| --- | --- |
| `xelo scan <path>` | Scan a local directory and generate SBOM output in the selected format. |
| `xelo scan <url>` | Clone a git repository, scan it, and generate SBOM output. |
| `xelo validate <file>` | Validate a Xelo-native JSON document against the bundled schema. |
| `xelo schema` | Print (or write) the Xelo JSON schema. |

## Global Flags

These flags are accepted at the root command level.

| Flag | Type | Required | Default | Behavior |
| --- | --- | --- | --- | --- |
| `--verbose`, `-v` | boolean | No | `false` | Enables INFO-level logging to stderr |
| `--debug` | boolean | No | `false` | Enables DEBUG logging and full tracebacks on errors |

## `scan path` Reference

Usage:

```bash
xelo scan <path> --output <file> [options]
```

| Argument / Flag | Type | Required | Default | Behavior | Interactions |
| --- | --- | --- | --- | --- | --- |
| `<path>` | path | Yes | none | Local directory to scan | Fails if missing or not a directory |
| `--output <file>` | path | Yes | none | Output file path | Required for all formats |
| `--format <json\|cyclonedx\|unified>` | enum | No | `json` | Output format selection | `unified` generates a standard CycloneDX BOM and merges AI-BOM data |
| `--llm` | boolean | No | `false` | Enables LLM enrichment for this run | When omitted, deterministic extraction is used |
| `--llm-model <model>` | string | No | from config/env (`XELO_LLM_MODEL`, fallback `gpt-4o-mini`) | LLM model identifier | Used when LLM enrichment is active |
| `--llm-budget-tokens <n>` | integer | No | from config/env (`XELO_LLM_BUDGET_TOKENS`, fallback `50000`) | Token budget for enrichment | Used when LLM enrichment is active |
| `--llm-api-key <key>` | string | No | from config/env/provider defaults | Direct API key override | Sensitive; do not log/share |
| `--llm-api-base <url>` | string | No | from config/env/provider defaults | Base URL override (for hosted endpoints) | Common for Azure/provider proxies |

## `scan repo` Reference

Usage:

```bash
xelo scan <url> --output <file> [options]
```

| Argument / Flag | Type | Required | Default | Behavior | Interactions |
| --- | --- | --- | --- | --- | --- |
| `<url>` | string (git URL) | Yes | none | Repository URL to clone and scan | Requires `git` on `PATH` |
| `--ref <ref>` | string | No | `main` | Git ref/branch/tag to scan | Invalid refs fail clone/checkout |
| `--output <file>` | path | Yes | none | Output file path | Required for all formats |
| `--format <json\|cyclonedx\|unified>` | enum | No | `json` | Output format selection | `unified` generates a standard CycloneDX BOM and merges AI-BOM data |
Same LLM flags as `scan path` are also accepted here with identical behavior.

## `validate` Reference

Usage:

```bash
xelo validate <file>
```

Validates a Xelo-native JSON document against the bundled `aibom.schema.json`.

| Argument | Type | Required | Behavior |
| --- | --- | --- | --- |
| `<file>` | path | Yes | Path to the JSON file to validate. Exits `0` and prints `OK — document is valid` on success; exits `1` and prints `error: validation failed: …` on failure. |


## `schema` Reference

Usage:

```bash
xelo schema [--output <file>]
```

Emits the Xelo JSON schema (JSON Schema 2020-12, `$id` `https://nuguard.ai/schemas/aibom/1.1.0/aibom.schema.json`).

| Flag | Type | Required | Default | Behavior |
| --- | --- | --- | --- | --- |
| `--output <file>` | path | No | stdout | Write schema to a file instead of printing to stdout. |

---

## Behavior Notes

- CLI flags override environment-backed defaults from runtime config.
- `--llm` is the scan-time switch for enrichment; when omitted, scans run deterministic-only.
- Unified mode always generates a standard CycloneDX BOM automatically before merging AI-BOM data.
- If `cyclonedx-py` is unavailable, unified generation can fall back to a shallow dependency scanner.
- Dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`) are discovered recursively at any depth in the project tree; virtual-environment and build directories (`.venv`, `node_modules`, `dist`, etc.) are excluded automatically.

## Toolbox Plugins

Xelo's built-in analysis plugins (`xelo.toolbox.plugins`) are invoked **programmatically** — they are not sub-commands on the `xelo` binary. The typical workflow is:

1. Run `xelo scan` to produce a JSON SBOM.
2. Load the SBOM in Python and run whichever plugins you need.
3. Write the results to files (SARIF, Markdown, etc.).

**Quick one-liner (shell):**

```bash
xelo scan ./my-repo --output sbom.json
python - sbom.json <<'EOF'
import json, sys
from xelo.toolbox.plugins.vulnerability import VulnerabilityScannerPlugin
from xelo.toolbox.plugins.atlas_annotator import AtlasAnnotatorPlugin
from xelo.toolbox.plugins.sarif_exporter import SarifExporterPlugin
from xelo.toolbox.plugins.markdown_exporter import MarkdownExporterPlugin

sbom = json.loads(open(sys.argv[1]).read())

vuln = VulnerabilityScannerPlugin().run(sbom, {})
print(vuln.status, vuln.message)

atlas = AtlasAnnotatorPlugin().run(sbom, {})
for f in atlas.details["findings"]:
    print(f["rule_id"], f["severity"])

sarif = SarifExporterPlugin().run(sbom, {})
open("results.sarif", "w").write(sarif.details["sarif_json"])

md = MarkdownExporterPlugin().run(sbom, {})
open("report.md", "w").write(md.details["markdown"])
EOF
```

### Available Plugins

| Class | Module | Network | Notes |
| --- | --- | --- | --- |
| `VulnerabilityScannerPlugin` | `vulnerability` | No | Structural VLA rules — missing guardrails, over-privileged agents |
| `AtlasAnnotatorPlugin` | `atlas_annotator` | No | Maps findings to MITRE ATLAS v2 techniques and mitigations |
| `PolicyAssessmentPlugin` | `policy_assessment` | No | Evaluates SBOM against a custom policy file; `config={"policy_file": "<path>"}` |
| `LicenseCheckerPlugin` | `license_checker` | No | Checks dependency licence compliance |
| `DependencyAnalyzerPlugin` | `dependency` | No | Scores dependency freshness; flags outdated AI packages |
| `SarifExporterPlugin` | `sarif_exporter` | No | Exports findings as SARIF 2.1.0 (GitHub Code Scanning compatible) |
| `CycloneDxExporter` | `cyclonedx_exporter` | No | Exports nodes as CycloneDX 1.6 |
| `MarkdownExporterPlugin` | `markdown_exporter` | No | Human-readable Markdown report |
| `GhasUploaderPlugin` | `ghas_uploader` | Yes | Uploads SARIF to GitHub Advanced Security; requires `GITHUB_TOKEN` |
| `AwsSecurityHubPlugin` | `aws_security_hub` | Yes | Pushes findings to AWS Security Hub; requires `boto3` + AWS credentials |
| `XrayPlugin` | `xray` | Yes | Pushes findings to JFrog Xray; requires URL + credentials |

All classes are importable from `xelo.toolbox.plugins.<module>` (e.g. `from xelo.toolbox.plugins.sarif_exporter import SarifExporterPlugin`).

Each plugin call returns a `ToolResult` with:

| Field | Type | Description |
| --- | --- | --- |
| `status` | `"ok"` \| `"error"` \| `"warning"` | Outcome of the run |
| `message` | str | One-line human-readable summary |
| `details` | dict | Plugin-specific payload (findings list, sarif_json, markdown, …) |

For full Python API examples see the [Developer Guide](./developer-guide.md).

### Third-Party / Custom Plugins

Anyone can ship a custom detection adapter by subclassing `xelo.plugins.PluginAdapter` and registering it under the `xelo.plugins` entry-point group.

```toml
# pyproject.toml — in a third-party package
[project.entry-points."xelo.plugins"]
my_adapter = "my_package.adapter:MyAdapter"
```

To enable plugin discovery when scanning, pass `--plugins` is not a CLI flag today — use the Python API:

```python
from xelo import AiSbomExtractor, AiSbomConfig

extractor = AiSbomExtractor(load_plugins=True)
doc = extractor.extract_from_path("./my-repo", config=AiSbomConfig())
```

Or call `xelo.plugins.load_plugins()` directly before constructing the extractor.

---

## Detected Component Types

Xelo assigns each detected item one of the following `component_type` values in the output JSON:

| Type | Examples |
| --- | --- |
| `AGENT` | Agent class instances, function-based handlers |
| `MODEL` | LLM model names (gpt-4o, gemini-2.0-flash, etc.) |
| `TOOL` | Tool-decorated functions, registered tools |
| `PROMPT` | System prompts, prompt templates |
| `DATASTORE` | Vector stores, databases (chroma, postgres, redis, etc.) |
| `FRAMEWORK` | AI framework in use (langgraph, crewai, openai-agents, etc.) |
| `GUARDRAIL` | Guardrails AI guards and validators |
| `AUTH` | Authentication patterns |
| `DEPLOYMENT` | Deployment configs (Docker, k8s, CI/CD) |
| `CONTAINER_IMAGE` | Docker base images |
| `API_ENDPOINT` | Exposed API endpoints |
| `MCP_SERVER` | MCP server definitions |

## LLM Configuration

`scan` commands support these LLM-related options:

- `--llm`: enable enrichment for this run.
- `--llm-model <model>`: provider/model identifier (litellm-compatible string).
- `--llm-budget-tokens <n>`: token budget across enrichment calls.
- `--llm-api-key <key>`: explicit API key override.
- `--llm-api-base <url>`: explicit API base URL override.

Environment variables consumed by Xelo directly:

- `XELO_LLM=true|false`
- `XELO_LLM_MODEL=<model-string>`
- `XELO_LLM_BUDGET_TOKENS=<int>`
- `XELO_LLM_API_KEY=<key>`
- `XELO_LLM_API_BASE=<url>`
- `GEMINI_API_KEY` or `GOOGLE_CLOUD_API_KEY` (for direct Vertex AI mode when using `vertex_ai/*` models)
- `VERTEXAI_LOCATION` (reserved for Vertex location metadata)

Provider-native variables are also supported through litellm, depending on provider setup (for example `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, Azure OpenAI variables, or AWS credentials for Bedrock).

## LLM Provider Examples

OpenAI:

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=gpt-4o-mini
export OPENAI_API_KEY=your_openai_key
xelo scan ./my-repo --format json --output sbom.json --llm
```

Gemini (via litellm):

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=gemini/gemini-2.0-flash
export GOOGLE_API_KEY=your_google_ai_studio_key
xelo scan ./my-repo --output sbom.json --llm
```

Anthropic:

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=anthropic/claude-3-5-sonnet-latest
export ANTHROPIC_API_KEY=your_anthropic_key
xelo scan ./my-repo --output sbom.json --llm
```

Azure OpenAI:

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=azure/gpt-4o-mini
export AZURE_API_KEY=your_azure_openai_key
export AZURE_API_BASE=https://<resource>.openai.azure.com/
export AZURE_API_VERSION=2024-10-21
xelo scan ./my-repo --output sbom.json --llm
```

Vertex AI Gemini (direct Vertex path in Xelo):

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=vertex_ai/gemini-2.5-flash
export GEMINI_API_KEY=your_vertex_key
xelo scan ./my-repo --output sbom.json --llm
```

Bedrock Claude:

```bash
export XELO_LLM=true
export XELO_LLM_MODEL=bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
xelo scan ./my-repo --output sbom.json --llm
```

## Exit and Error Conventions

- On success: command-specific stdout summary is printed.
- On failure: stderr includes `error: <message>`.
- With `--debug`, full traceback is printed before the error line.

## Examples

Local scan:

```bash
xelo scan ./my-repo --format json --output sbom.json
```

Remote repo scan:

```bash
xelo scan https://github.com/example/project.git --ref main --format json --output sbom.json
```

Unified output (auto-generates standard CycloneDX BOM):

```bash
xelo scan ./my-repo --format unified --output unified-bom.json
```

## Constraints

- `scan repo` requires `git` available on `PATH`.
- LLM enrichment requires optional dependency support (`litellm`) and provider credentials.
- Best standard dependency BOM fidelity in unified mode requires `cyclonedx-py` availability.
- Repositories with no package manifest files (no `requirements.txt`, `pyproject.toml`, or `package.json` anywhere in the tree) will produce `deps: []` in output — this is expected for documentation-only or walkthrough repos.
