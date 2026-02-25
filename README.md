# Xelo

Xelo is an open-source AI SBOM generator for agentic and LLM-powered applications.
It scans code and configuration, produces AI-BOM JSON, and can export CycloneDX-compatible output for security and compliance workflows.

## Why Xelo

- Detects AI-specific components (agents, models, tools, prompts, datastores, auth, deployment artifacts).
- Works on mixed Python and TypeScript repositories.
- Uses deterministic extraction by default.
- Supports optional LLM enrichment when you explicitly enable it.

## Installation

Install from PyPI:

```bash
pip install xelo
```

Install for deXelopment:

```bash
pip install -e ".[dev]"
```

## Quickstart

Generate an AI-BOM from a local path:

```bash
Xelo scan path ./my-repo --format json --output sbom.json
```

Validate a generated document:

```bash
Xelo validate sbom.json
```

Export the JSON schema used by the models:

```bash
Xelo schema --output ai_bom.schema.json
```

CLI alias: `ai-sbom`.

## CLI Commands

| Command | Description |
| --- | --- |
| `Xelo scan path <PATH>` | Scan a local repository path |
| `Xelo scan repo <URL>` | Clone and scan a remote repository |
| `Xelo validate <FILE>` | Validate AI-BOM JSON against schema models |
| `Xelo schema --output <FILE>` | Export schema JSON |

Run `Xelo --help` or `Xelo <command> --help` for all flags.

## Configuration

`Xelo scan` can be configured via `.env` values and CLI flags. CLI flags take precedence.

Environment variables:

- `AISBOM_DETERMINISTIC_ONLY=true|false`
- `AISBOM_LLM_MODEL=<litellm model string>`
- `AISBOM_LLM_BUDGET_TOKENS=<int>`
- `AISBOM_LLM_API_KEY=<optional key>`

Example enabling enrichment:

```bash
Xelo scan path ./my-repo --enable-llm --llm-model gpt-4o-mini --output sbom.json
```

## DeXelopment

```bash
pip install -e ".[dev]"
ruff check src tests
mypy src
pytest
```

## Project Docs

- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)
- [Support](./SUPPORT.md)
- [Governance](./GOVERNANCE.md)
- [Roadmap](./ROADMAP.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)

## License

Apache-2.0. See [LICENSE](./LICENSE).
