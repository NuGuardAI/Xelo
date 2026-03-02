# Getting Started

This guide gets you from install to a validated AI-BOM in a few commands.

## Prerequisites

- Python `3.11` or newer
- Optional: `git` on `PATH` (required for `xelo scan repo <url>`)
- Optional: `cyclonedx-py` CLI for highest-fidelity standard dependency SBOM generation in unified mode

## Install

Install base package:

```bash
pip install xelo
```

Install optional extras by use case:

```bash
# Better TypeScript/JavaScript parsing
pip install "xelo[ts]"

# CycloneDX standard SBOM generation support
pip install "xelo[cdx]"

# LLM enrichment support
pip install "xelo[llm]"
```

## Quickstart

Run a local scan and write Xelo-native JSON:

```bash
xelo scan path ./my-repo --format json --output sbom.json
```

Validate the generated JSON against the `AiBomDocument` schema:

```bash
xelo validate sbom.json
```

Export the JSON schema:

```bash
xelo schema --output ai_bom.schema.json
```

CLI alias:

```bash
ai-sbom scan path ./my-repo --format json --output sbom.json
```

## Expected Success Output

`scan` prints a success summary to stdout:

```text
<nodes> nodes, <edges> edges → <output-file>
```

`validate` prints:

```text
OK — document is valid
```

`schema` prints:

```text
schema written → <output-file>
```

## Configuration Basics

`xelo scan` can be configured with environment variables and CLI flags. CLI flags override env values.

Common environment variables:

- `AISBOM_ENABLE_LLM=true|false`
- `AISBOM_LLM_MODEL=<litellm-model-string>`
- `AISBOM_LLM_BUDGET_TOKENS=<int>`
- `AISBOM_LLM_API_KEY=<api-key>`
- `AISBOM_LLM_API_BASE=<base-url>`

Example enabling LLM enrichment:

```bash
xelo scan path ./my-repo --enable-llm --llm-model gpt-4o-mini --output sbom.json
```

## Next Steps

- For complete command details, see [CLI Reference](./cli-reference.md)
- If a command fails, see [Troubleshooting](./troubleshooting.md)
- To contribute, see [Developer Guide](./developer-guide.md)
