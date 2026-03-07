# Developer Guide

This guide is for application developers who want to use Xelo as a Python library to extract AI SBOM data from repositories.

## Install

```bash
pip install xelo
```

All features are included.

## Core API

Import the public library surface:

```python
from xelo import AiSbomConfig, AiSbomExtractor, AiSbomSerializer
```

Main types:

- `AiSbomExtractor`: runs extraction on local paths or git repositories.
- `AiSbomConfig`: controls scan scope and enrichment behavior.
- `AiSbomSerializer`: converts extracted documents to JSON or CycloneDX.

## Extract From a Git Repository

`extract_from_repo` is the direct library API for remote repositories.

```python
from xelo import AiSbomConfig, AiSbomExtractor, AiSbomSerializer

extractor = AiSbomExtractor()
config = AiSbomConfig()  # deterministic by default

doc = extractor.extract_from_repo(
    url="https://github.com/example/project.git",
    ref="main",
    config=config,
)

json_text = AiSbomSerializer.to_json(doc)
print(f"nodes={len(doc.nodes)} edges={len(doc.edges)}")
```

## Extract From a Local Path

If you already have a checked-out repo:

```python
from pathlib import Path
from xelo import AiSbomConfig, AiSbomExtractor

extractor = AiSbomExtractor()
doc = extractor.extract_from_path(
    path=Path("/path/to/repo"),
    config=AiSbomConfig(),
    source_ref="https://github.com/example/project.git",
    branch="main",
)
```

## Enable LLM Enrichment

LLM enrichment is off by default in library usage (`enable_llm=False`).
Enable it explicitly in code:

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="gpt-4o-mini",
    llm_budget_tokens=50_000,
)
```

Useful environment variables:

- `XELO_LLM`
- `XELO_LLM_MODEL`
- `XELO_LLM_BUDGET_TOKENS`
- `XELO_LLM_API_KEY`
- `XELO_LLM_API_BASE`

Additional provider-native variables can also be used through litellm (for example `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, Azure OpenAI variables, or AWS credentials for Bedrock).

## Provider Config Examples (Python Library)

OpenAI:

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="gpt-4o-mini",
)
# Set OPENAI_API_KEY in env, or pass llm_api_key="..."
```

Gemini (via litellm):

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="gemini/gemini-2.0-flash",
)
# Set GOOGLE_API_KEY in env, or pass llm_api_key="..."
```

Anthropic:

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="anthropic/claude-3-5-sonnet-latest",
)
# Set ANTHROPIC_API_KEY in env, or pass llm_api_key="..."
```

Azure OpenAI:

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="azure/gpt-4o-mini",
    llm_api_key="your_azure_openai_key",
    llm_api_base="https://<resource>.openai.azure.com/",
)
# You may also need AZURE_API_VERSION in env.
```

Vertex AI Gemini (direct Vertex path in Xelo):

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="vertex_ai/gemini-2.5-flash",
)
# Set GEMINI_API_KEY or GOOGLE_CLOUD_API_KEY in env.
```

Bedrock Claude:

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
)
# Set AWS_REGION and AWS credentials in env (or IAM role).
```

## Inspect Extracted Data

Useful fields on the returned `AiSbomDocument`:

```python
# Detected AI components
for node in doc.nodes:
    print(node.component_type, node.name, node.metadata)

# Directed relationships between components
for edge in doc.edges:
    print(edge.source, edge.relationship_type, edge.target)

# Package dependencies (from requirements.txt / pyproject.toml / package.json)
# Scanned recursively at any depth in the repo tree
for dep in doc.deps:
    print(dep.name, dep.version_spec, dep.purl, dep.source_file)

# Scan-level summary: frameworks, modalities, data classification
print(doc.summary.frameworks)   # e.g. ['langgraph', 'openai_agents']
print(doc.summary.modalities)   # e.g. ['text', 'audio']
```

## Supported Frameworks

Xelo detects components from the following frameworks without additional config:

**Python:** LangChain, LangGraph, OpenAI Agents SDK, CrewAI (code + YAML configs), AutoGen (code + YAML configs), Google ADK, LlamaIndex, Agno, AWS BedrockAgentCore, Azure AI Agent Service, Guardrails AI, MCP Server, Semantic Kernel

**TypeScript / JavaScript:** LangChain.js, LangGraph.js, OpenAI Agents (TS), Azure AI Agents (TS), Agno (TS), MCP Server (TS)

## Serialize Output

Xelo-native JSON:

```python
from xelo import AiSbomSerializer

json_text = AiSbomSerializer.to_json(doc)
```

CycloneDX JSON:

```python
from xelo import AiSbomSerializer

cyclonedx_dict = AiSbomSerializer.to_cyclonedx(doc)
```

CycloneDX JSON string:

```python
from xelo import AiSbomSerializer

cyclonedx_text = AiSbomSerializer.dump_cyclonedx_json(doc)
```

## Minimal End-to-End Example

```python
from pathlib import Path
from xelo import AiSbomConfig, AiSbomExtractor, AiSbomSerializer

extractor = AiSbomExtractor()
config = AiSbomConfig()

doc = extractor.extract_from_repo(
    url="https://github.com/example/project.git",
    ref="main",
    config=config,
)

Path("ai-sbom.json").write_text(AiSbomSerializer.to_json(doc), encoding="utf-8")
Path("ai-sbom.cdx.json").write_text(
    AiSbomSerializer.dump_cyclonedx_json(doc),
    encoding="utf-8",
)
```

## Operational Notes

- `extract_from_repo` requires `git` available on `PATH`.
- Very large repositories may need config tuning (`max_files`, `max_file_size_bytes`).
- If LLM enrichment fails, extraction still returns deterministic output.
- For command-line usage, see [CLI Reference](./cli-reference.md).
