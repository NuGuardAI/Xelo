# Getting Started

This guide gets you from install to your first AI-BOM in a few commands.

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

CLI alias:

```bash
ai-sbom scan path ./my-repo --format json --output sbom.json
```

## Understanding Scan Output

A successful `scan` prints a summary to stdout:

```text
<nodes> nodes, <edges> edges → <output-file>
```

The generated JSON document includes:

- `nodes` — detected AI components (agents, models, tools, prompts, datastores, guardrails, auth, deployment, framework)
- `edges` — directed relationships between components
- `deps` — package dependencies collected from `requirements.txt`, `pyproject.toml`, and `package.json` files found anywhere in the project tree
- `summary` — scan-level metadata including `frameworks` (list of detected AI frameworks), `modalities`, and data classification signals

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

## Supported Frameworks

Xelo detects components from the following frameworks without any additional config:

**Python:** LangChain, LangGraph, OpenAI Agents SDK, CrewAI (code + YAML configs), AutoGen (code + YAML configs), Google ADK, LlamaIndex, Agno, AWS BedrockAgentCore, Azure AI Agent Service, Guardrails AI, MCP Server, Semantic Kernel

**TypeScript / JavaScript:** LangChain.js, LangGraph.js, OpenAI Agents (TS), Azure AI Agents (TS), Agno (TS), MCP Server (TS)

## Next Steps

- For complete command details, see [CLI Reference](./cli-reference.md)
- If a command fails, see [Troubleshooting](./troubleshooting.md)
- To use Xelo as a Python library, see [Developer Guide](./developer-guide.md)
