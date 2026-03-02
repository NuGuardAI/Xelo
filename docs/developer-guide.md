# Developer Guide

This guide is for application developers who want to use Xelo as a Python library to extract AI SBOM data from repositories.

## Install

```bash
pip install xelo
```

Optional extras:

```bash
# Better TypeScript/JavaScript parsing support
pip install "xelo[ts]"

# Unified CycloneDX generation support
pip install "xelo[cdx]"

# LLM enrichment support
pip install "xelo[llm]"
```

## Core API

Import the public library surface:

```python
from xelo import ExtractionConfig, SbomExtractor, SbomSerializer
```

Main types:

- `SbomExtractor`: runs extraction on local paths or git repositories.
- `ExtractionConfig`: controls scan scope and enrichment behavior.
- `SbomSerializer`: converts extracted documents to JSON or CycloneDX.

## Extract From a Git Repository

`extract_from_repo` is the direct library API for remote repositories.

```python
from xelo import ExtractionConfig, SbomExtractor, SbomSerializer

extractor = SbomExtractor()
config = ExtractionConfig()  # deterministic by default

doc = extractor.extract_from_repo(
    url="https://github.com/example/project.git",
    ref="main",
    config=config,
)

json_text = SbomSerializer.to_json(doc)
print(f"nodes={len(doc.nodes)} edges={len(doc.edges)}")
```

## Extract From a Local Path

If you already have a checked-out repo:

```python
from pathlib import Path
from xelo import ExtractionConfig, SbomExtractor

extractor = SbomExtractor()
doc = extractor.extract_from_path(
    path=Path("/path/to/repo"),
    config=ExtractionConfig(),
    source_ref="https://github.com/example/project.git",
    branch="main",
)
```

## Enable LLM Enrichment

LLM enrichment is off by default in library usage (`enable_llm=False`).
Enable it explicitly in code:

```python
from xelo import ExtractionConfig

config = ExtractionConfig(
    enable_llm=True,
    llm_model="gpt-4o-mini",
    llm_budget_tokens=50_000,
)
```

Useful environment variables:

- `AISBOM_ENABLE_LLM`
- `AISBOM_LLM_MODEL`
- `AISBOM_LLM_BUDGET_TOKENS`
- `AISBOM_LLM_API_KEY`
- `AISBOM_LLM_API_BASE`

## Serialize Output

Xelo-native JSON:

```python
from xelo import SbomSerializer

json_text = SbomSerializer.to_json(doc)
```

CycloneDX JSON:

```python
from xelo import SbomSerializer

cyclonedx_dict = SbomSerializer.to_cyclonedx(doc)
```

CycloneDX JSON string:

```python
from xelo import SbomSerializer

cyclonedx_text = SbomSerializer.dump_cyclonedx_json(doc)
```

## Minimal End-to-End Example

```python
from pathlib import Path
from xelo import ExtractionConfig, SbomExtractor, SbomSerializer

extractor = SbomExtractor()
config = ExtractionConfig()

doc = extractor.extract_from_repo(
    url="https://github.com/example/project.git",
    ref="main",
    config=config,
)

Path("ai-sbom.json").write_text(SbomSerializer.to_json(doc), encoding="utf-8")
Path("ai-sbom.cdx.json").write_text(
    SbomSerializer.dump_cyclonedx_json(doc),
    encoding="utf-8",
)
```

## Operational Notes

- `extract_from_repo` requires `git` available on `PATH`.
- Very large repositories may need config tuning (`max_files`, `max_file_size_bytes`).
- If LLM enrichment fails, extraction still returns deterministic output.
- For command-line usage, see [CLI Reference](./cli-reference.md).
