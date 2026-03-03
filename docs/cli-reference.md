# CLI Reference

Xelo CLI command entry points:

- Primary: `xelo`
- Alias: `ai-sbom`

## Command Map

| Command | Purpose |
| --- | --- |
| `xelo scan path <path>` | Scan a local directory and generate SBOM output in the selected format. |
| `xelo scan repo <url>` | Clone a git repository, scan it, and generate SBOM output. |
| `xelo validate <file>` | Validate a Xelo-native JSON document against the `AiBomDocument` schema. |
| `xelo schema --output <file>` | Export the current `AiBomDocument` JSON schema to a file. |

## Global Flags

These flags are accepted at the root command level.

| Flag | Type | Required | Default | Behavior |
| --- | --- | --- | --- | --- |
| `--verbose`, `-v` | boolean | No | `false` | Enables INFO-level logging to stderr |
| `--debug` | boolean | No | `false` | Enables DEBUG logging and full tracebacks on errors |

## `scan path` Reference

Usage:

```bash
xelo scan path <path> --output <file> [options]
```

| Argument / Flag | Type | Required | Default | Behavior | Interactions |
| --- | --- | --- | --- | --- | --- |
| `<path>` | path | Yes | none | Local directory to scan | Fails if missing or not a directory |
| `--output <file>` | path | Yes | none | Output file path | Required for all formats |
| `--format <json\|cyclonedx\|unified>` | enum | No | `json` | Output format selection | `unified` generates a standard CycloneDX BOM and merges AI-BOM data |
| `--enable-llm` | boolean | No | `false` | Enables LLM enrichment for this run | When omitted, deterministic extraction is used |
| `--llm-model <model>` | string | No | from config/env (`AISBOM_LLM_MODEL`, fallback `gpt-4o-mini`) | LLM model identifier | Used when LLM enrichment is active |
| `--llm-budget-tokens <n>` | integer | No | from config/env (`AISBOM_LLM_BUDGET_TOKENS`, fallback `50000`) | Token budget for enrichment | Used when LLM enrichment is active |
| `--llm-api-key <key>` | string | No | from config/env/provider defaults | Direct API key override | Sensitive; do not log/share |
| `--llm-api-base <url>` | string | No | from config/env/provider defaults | Base URL override (for hosted endpoints) | Common for Azure/provider proxies |

## `scan repo` Reference

Usage:

```bash
xelo scan repo <url> --output <file> [options]
```

| Argument / Flag | Type | Required | Default | Behavior | Interactions |
| --- | --- | --- | --- | --- | --- |
| `<url>` | string (git URL) | Yes | none | Repository URL to clone and scan | Requires `git` on `PATH` |
| `--ref <ref>` | string | No | `main` | Git ref/branch/tag to scan | Invalid refs fail clone/checkout |
| `--output <file>` | path | Yes | none | Output file path | Required for all formats |
| `--format <json\|cyclonedx\|unified>` | enum | No | `json` | Output format selection | `unified` generates a standard CycloneDX BOM and merges AI-BOM data |
| `--enable-llm` | boolean | No | `false` | Enables LLM enrichment for this run | When omitted, deterministic extraction is used |
| `--llm-model <model>` | string | No | from config/env | LLM model identifier | Used when LLM enrichment is active |
| `--llm-budget-tokens <n>` | integer | No | from config/env | Token budget for enrichment | Used when LLM enrichment is active |
| `--llm-api-key <key>` | string | No | from config/env/provider defaults | Direct API key override | Sensitive; do not log/share |
| `--llm-api-base <url>` | string | No | from config/env/provider defaults | Base URL override | Common for Azure/provider proxies |

## `validate` Reference

Usage:

```bash
xelo validate <file>
```

| Argument | Type | Required | Default | Behavior |
| --- | --- | --- | --- | --- |
| `<file>` | path | Yes | none | Validates JSON file against `AiBomDocument` |

Success output:

```text
OK — document is valid
```

## `schema` Reference

Usage:

```bash
xelo schema --output <file>
```

| Flag | Type | Required | Default | Behavior |
| --- | --- | --- | --- | --- |
| `--output <file>` | path | Yes | none | Writes `AiBomDocument` JSON schema to file |

Success output:

```text
schema written → <output-file>
```

## Behavior Notes

- CLI flags override environment-backed defaults from runtime config.
- `--enable-llm` is the scan-time switch for enrichment; when omitted, scans run deterministic-only.
- Unified mode always generates a standard CycloneDX BOM automatically before merging AI-BOM data.
- If `cyclonedx-py` is unavailable, unified generation can fall back to a shallow dependency scanner.
- Dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`) are discovered recursively at any depth in the project tree; virtual-environment and build directories (`.venv`, `node_modules`, `dist`, etc.) are excluded automatically.

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

- `--enable-llm`: enable enrichment for this run.
- `--llm-model <model>`: provider/model identifier (litellm-compatible string).
- `--llm-budget-tokens <n>`: token budget across enrichment calls.
- `--llm-api-key <key>`: explicit API key override.
- `--llm-api-base <url>`: explicit API base URL override.

Environment variables consumed by Xelo directly:

- `AISBOM_ENABLE_LLM=true|false`
- `AISBOM_LLM_MODEL=<model-string>`
- `AISBOM_LLM_BUDGET_TOKENS=<int>`
- `AISBOM_LLM_API_KEY=<key>`
- `AISBOM_LLM_API_BASE=<url>`
- `GEMINI_API_KEY` or `GOOGLE_CLOUD_API_KEY` (for direct Vertex AI mode when using `vertex_ai/*` models)
- `VERTEXAI_LOCATION` (reserved for Vertex location metadata)

Provider-native variables are also supported through litellm, depending on provider setup (for example `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, Azure OpenAI variables, or AWS credentials for Bedrock).

## LLM Provider Examples

OpenAI:

```bash
export AISBOM_ENABLE_LLM=true
export AISBOM_LLM_MODEL=gpt-4o-mini
export OPENAI_API_KEY=your_openai_key
xelo scan path ./my-repo --format json --output sbom.json --enable-llm
```

Gemini (via litellm):

```bash
export AISBOM_ENABLE_LLM=true
export AISBOM_LLM_MODEL=gemini/gemini-2.0-flash
export GOOGLE_API_KEY=your_google_ai_studio_key
xelo scan path ./my-repo --output sbom.json --enable-llm
```

Anthropic:

```bash
export AISBOM_ENABLE_LLM=true
export AISBOM_LLM_MODEL=anthropic/claude-3-5-sonnet-latest
export ANTHROPIC_API_KEY=your_anthropic_key
xelo scan path ./my-repo --output sbom.json --enable-llm
```

Azure OpenAI:

```bash
export AISBOM_ENABLE_LLM=true
export AISBOM_LLM_MODEL=azure/gpt-4o-mini
export AZURE_API_KEY=your_azure_openai_key
export AZURE_API_BASE=https://<resource>.openai.azure.com/
export AZURE_API_VERSION=2024-10-21
xelo scan path ./my-repo --output sbom.json --enable-llm
```

Vertex AI Gemini (direct Vertex path in Xelo):

```bash
export AISBOM_ENABLE_LLM=true
export AISBOM_LLM_MODEL=vertex_ai/gemini-2.5-flash
export GEMINI_API_KEY=your_vertex_key
xelo scan path ./my-repo --output sbom.json --enable-llm
```

Bedrock Claude:

```bash
export AISBOM_ENABLE_LLM=true
export AISBOM_LLM_MODEL=bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
xelo scan path ./my-repo --output sbom.json --enable-llm
```

## Exit and Error Conventions

- On success: command-specific stdout summary is printed.
- On failure: stderr includes `error: <message>`.
- With `--debug`, full traceback is printed before the error line.

## Examples

Local scan:

```bash
xelo scan path ./my-repo --format json --output sbom.json
```

Remote repo scan:

```bash
xelo scan repo https://github.com/example/project.git --ref main --format json --output sbom.json
```

Unified output (auto-generates standard CycloneDX BOM):

```bash
xelo scan path ./my-repo --format unified --output unified-bom.json
```

Schema export and validation:

```bash
xelo schema --output ai_bom.schema.json
xelo validate sbom.json
```

## Constraints

- `scan repo` requires `git` available on `PATH`.
- LLM enrichment requires optional dependency support (`litellm`) and provider credentials.
- Best standard dependency BOM fidelity in unified mode requires `cyclonedx-py` availability.
- Repositories with no package manifest files (no `requirements.txt`, `pyproject.toml`, or `package.json` anywhere in the tree) will produce `deps: []` in output — this is expected for documentation-only or walkthrough repos.
