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
