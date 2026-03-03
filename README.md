# Xelo

Xelo is an open-source AI SBOM generator for agentic and LLM-powered applications.
It scans code and configuration, produces AI-BOM JSON, and can export CycloneDX-compatible output for security and compliance workflows.

## Why Xelo

- Detects AI-specific components (agents, models, tools, prompts, datastores, guardrails, auth, deployment artifacts).
- Works on mixed Python and TypeScript repositories.
- Recursively scans `requirements.txt`, `pyproject.toml`, and `package.json` files at any depth in the project tree.
- Uses deterministic extraction by default.
- Supports optional LLM enrichment when you explicitly enable it.

## Supported Frameworks

Xelo detects components from the following AI/agent frameworks out of the box:

**Python:** LangChain, LangGraph, OpenAI Agents SDK, CrewAI (code + YAML configs), AutoGen (code + YAML configs), Google ADK, LlamaIndex, Agno, AWS BedrockAgentCore, Azure AI Agent Service, Guardrails AI, MCP Server, Semantic Kernel

**TypeScript / JavaScript:** LangChain.js, LangGraph.js, OpenAI Agents (TS), Azure AI Agents (TS), Agno (TS), MCP Server (TS)

## Installation

Install from PyPI:

```bash
pip install xelo
```

Install for development:

```bash
pip install -e ".[dev]"
```

## Quickstart

Generate an AI-BOM from a local path:

```bash
xelo scan path ./my-repo --format json --output sbom.json
```

CLI alias: `ai-sbom`.

## CLI Commands

| Command | Description |
| --- | --- |
| `xelo scan path <PATH>` | Scan a local repository path |
| `xelo scan repo <URL>` | Clone and scan a remote repository |

Run `xelo --help` or `xelo <command> --help` for all flags.

## Configuration

`xelo scan` can be configured via `.env` values and CLI flags. CLI flags take precedence.

Environment variables:

- `AISBOM_ENABLE_LLM=true|false`
- `AISBOM_LLM_MODEL=<litellm model string>`
- `AISBOM_LLM_BUDGET_TOKENS=<int>`
- `AISBOM_LLM_API_KEY=<optional key>`

Example enabling enrichment:

```bash
xelo scan path ./my-repo --enable-llm --llm-model gpt-4o-mini --output sbom.json
```

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
mypy src
pytest
```

## Project Docs

- [Documentation Index](./docs/README.md)
- [Getting Started](./docs/getting-started.md)
- [CLI Reference](./docs/cli-reference.md)
- [Developer Guide](./docs/developer-guide.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Documentation Changelog](./docs/CHANGELOG.md)
- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)
- [Support](./SUPPORT.md)
- [Governance](./GOVERNANCE.md)
- [Roadmap](./ROADMAP.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)

## License

Apache-2.0. See [LICENSE](./LICENSE).
