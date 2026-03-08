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
| `xelo plugin list` | List all available toolbox plugins with descriptions. |
| `xelo plugin run <plugin> <sbom>` | Run a named toolbox plugin against an existing SBOM JSON file. |

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
| `--plugin <name>` | string | No | none | Run a toolbox plugin inline after scanning — no intermediate file needed | Accepts any name from `xelo plugin list` |
| `--plugin-output <file>` | path | No | stdout | Output file for the plugin result | Only meaningful with `--plugin` |
| `--plugin-config key=value` | string | No | — | Plugin config entry (repeatable) | Only meaningful with `--plugin`; same syntax as `--config` in `plugin run` |

### Scan + Plugin in one command

Passing `--plugin` runs the chosen toolbox plugin immediately after extraction using the in-memory SBOM — no intermediate file required.

```bash
# Scan and run the vulnerability plugin in a single command
xelo scan ./my-ai-app \
  --output sbom.json \
  --plugin vulnerability \
  --plugin-output findings.json
```

The SBOM is written to `sbom.json` first, then the vulnerability scanner runs against it and writes `findings.json`. Both steps share the same extraction result.

`--plugin-config` passes options straight through to the plugin:

```bash
# Scan a remote repo and generate a Markdown report in one step
xelo scan https://github.com/org/repo --ref main \
  --output sbom.json \
  --plugin markdown \
  --plugin-output report.md
```

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

Same LLM flags and `--plugin` / `--plugin-output` / `--plugin-config` flags as `scan path` are accepted here with identical behavior.

**Example — scan a GitHub repo and run the vulnerability plugin in one command:**

```bash
xelo scan https://github.com/org/my-ai-app --ref main \
  --output sbom.json \
  --plugin vulnerability \
  --plugin-output findings.json
```

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

Xelo's built-in analysis plugins are invoked via `xelo plugin run`. The typical workflow is:

1. Run `xelo scan` to produce a JSON SBOM.
2. Pass the SBOM through one or more plugins.
3. Write the results to files (SARIF, Markdown, CycloneDX, etc.).

### `xelo plugin list`

Prints all available plugins with their network requirements and descriptions.

```bash
xelo plugin list
```

### `xelo plugin run` Reference

Usage:

```bash
xelo plugin run <plugin> <sbom> [--output <file>] [--config key=value ...] [--config-file <json>]
```

| Argument / Flag | Type | Required | Default | Behavior |
| --- | --- | --- | --- | --- |
| `<plugin>` | string | Yes | — | Plugin name — see `xelo plugin list` |
| `<sbom>` | path | Yes | — | Path to a Xelo-native JSON SBOM file |
| `--output <file>` | path | No | stdout | Write plugin output to file |
| `--config key=value` | string | No | — | Plugin config entry (repeatable) |
| `--config-file <json>` | path | No | — | JSON config file (merged with `--config`; `--config` takes precedence) |

**Output format by plugin:**

| Plugin | `--output` content |
| --- | --- |
| `sarif` | SARIF 2.1.0 JSON document |
| `cyclonedx` | CycloneDX 1.6 BOM JSON |
| `markdown` | Markdown text |
| All others | Full `ToolResult` JSON (`{status, tool, message, details}`) |

**Examples:**

```bash
# Structural vulnerability scan (findings to stdout)
xelo plugin run vulnerability sbom.json

# Write vulnerability findings to JSON
xelo plugin run vulnerability sbom.json --output findings.json

# MITRE ATLAS annotation
xelo plugin run atlas sbom.json --output atlas.json

# SARIF export → GitHub Code Scanning
xelo plugin run sarif sbom.json --output results.sarif

# CycloneDX export
xelo plugin run cyclonedx sbom.json --output bom.cdx.json

# Human-readable Markdown report
xelo plugin run markdown sbom.json --output report.md

# Dependency analysis
xelo plugin run dependency sbom.json

# Licence compliance
xelo plugin run license sbom.json --output license-report.json

# Upload SARIF to GitHub Advanced Security
xelo plugin run ghas sbom.json \
  --config token=ghp_... \
  --config github_repo=owner/repo \
  --config ref=refs/heads/main \
  --config commit_sha=abc1234...

# Push to AWS Security Hub
xelo plugin run aws-security-hub sbom.json \
  --config region=us-east-1 \
  --config aws_account_id=123456789012

# Submit to JFrog Xray
xelo plugin run xray sbom.json \
  --config url=https://acme.jfrog.io \
  --config project=my-project \
  --config token=eyJ... \
  --config tenant_id=acme \
  --config application_id=my-app
```

### Available Plugins

| Class | Module | Network | Notes |
| --- | --- | --- | --- |
| `VulnerabilityScannerPlugin` | `vulnerability` | No | Structural VLA rules — missing guardrails, over-privileged agents |
| `AtlasAnnotatorPlugin` | `atlas_annotator` | No | Maps findings to MITRE ATLAS v2 techniques and mitigations |
| `LicenseCheckerPlugin` | `license_checker` | No | Checks dependency licence compliance |
| `DependencyAnalyzerPlugin` | `dependency` | No | Scores dependency freshness; flags outdated AI packages |
| `SarifExporterPlugin` | `sarif_exporter` | No | Exports findings as SARIF 2.1.0 (GitHub Code Scanning compatible) |
| `CycloneDxExporter` | `cyclonedx_exporter` | No | Exports nodes as CycloneDX 1.6 |
| `MarkdownExporterPlugin` | `markdown_exporter` | No | Human-readable Markdown report |
| `GhasUploaderPlugin` | `ghas_uploader` | Yes | Uploads SARIF to GitHub Advanced Security; requires `token`, `github_repo`, `ref`, `commit_sha` |
| `AwsSecurityHubPlugin` | `aws_security_hub` | Yes | Pushes findings to AWS Security Hub; requires `boto3` + `region`, `aws_account_id` |
| `XrayPlugin` | `xray` | Yes | Pushes findings to JFrog Xray; requires `url`, `project`, `token`, `tenant_id`, `application_id` |


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
