# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Package identity

The Python package is `ai_sbom` (under `src/`). The CLI entry points are `xelo` and `ai-sbom`, both pointing to `ai_sbom.cli:main`. The PyPI distribution name is `xelo`. README examples still reference the older `Xelo` brand; the authoritative CLI name in code is `xelo`.

## Commands

```bash
# Install for development (includes all optional extras)
pip install -e ".[dev]"

# Lint
ruff check src tests

# Type-check
mypy src

# Run all tests
pytest

# Run a single test file
pytest tests/test_extraction.py

# Run a single test by name
pytest tests/test_extraction.py::TestCustomerServiceBot::test_agents_detected

# Run only non-smoke tests (smoke tests need network + git)
pytest -m "not smoke"

# CLI (after install)
xelo scan path ./my-repo --format json --output sbom.json
xelo validate sbom.json
xelo schema --output ai_bom.schema.json
```

## Architecture

### Extraction pipeline (`src/ai_sbom/extractor.py`)

`SbomExtractor` orchestrates a 3-phase pipeline over every file in the target directory:

1. **Phase 1 — AST-aware adapters** (language-specific):
   - Python (`.py`, `.ipynb`): Python `ast` via `ast_parser.parse()` → `FrameworkAdapter.extract()`
   - TypeScript/JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`): tree-sitter (or regex fallback) via `core/ts_parser.py` → `TSFrameworkAdapter.extract()`
   - SQL (`.sql`): `DataClassificationSQLAdapter.scan()`
   - Dockerfiles: `DockerfileAdapter.scan()`

2. **Phase 2 — Regex fallbacks**: `RegexAdapter.detect()` runs on all files for non-framework signals (model names, datastores, auth keywords, etc.).

3. **Phase 3 — LLM enrichment** (optional, `ExtractionConfig(enable_llm=True)`): verifies uncertain nodes, re-aggregates confidence scores, refines use-case summary via `litellm`.

Results deduplicate on `(ComponentType, canonical_name)` and assemble into `AiBomDocument`.

### Adapter types (`src/ai_sbom/adapters/base.py`)

Two distinct adapter hierarchies:
- **`DetectionAdapter` / `RegexAdapter`** — legacy regex-only, returns `AdapterDetection`
- **`FrameworkAdapter`** — AST-aware, receives a `ParseResult`, returns `list[ComponentDetection]`; Python adapters live in `adapters/python/`, TypeScript adapters in `adapters/typescript/`

`FrameworkAdapter.can_handle(imports)` gates execution; adapters declare `handles_imports` (module name prefixes). Lower `priority` integer = higher precedence during dedup.

### Core data model (`src/ai_sbom/models.py`)

All types are Pydantic v2 `BaseModel`. The `AiBomDocument` is the root output:
- `nodes: list[Node]` — detected AI components (`ComponentType` enum in `types.py`)
- `edges: list[Edge]` — directed relationships (`RelationshipType` enum)
- `evidence: list[Evidence]` — detection evidence per node
- `deps: list[PackageDep]` — package manifest dependencies
- `summary: ScanSummary` — deterministic scan-level metadata (frameworks, modalities, deployment info, data classification)

The JSON schema is generated directly from `AiBomDocument.model_json_schema()`.

### Output formats

`SbomSerializer` (serializer.py) handles:
- `json` — Xelo-native `AiBomDocument` JSON
- `cyclonedx` — AI components only, CycloneDX 1.6
- `unified` — standard deps BOM (via `cyclonedx-bom` CLI or supplied file) merged with AI-BOM via `AiBomMerger` (merger.py)

### Key configuration (`src/ai_sbom/config.py`)

`ExtractionConfig` defaults to `enable_llm=False` (reads `AISBOM_ENABLE_LLM` env var; `AISBOM_DETERMINISTIC_ONLY` is accepted as a legacy alias). LLM enrichment requires `--enable-llm` flag or `AISBOM_ENABLE_LLM=true`. LLM calls go through `litellm` (`llm_client.py`).

### Test fixtures

`tests/fixtures/` contains realistic AI application code used by `test_extraction.py`:
- `fixtures/apps/` — multi-file scenario apps (customer_service_bot, research_assistant, rag_pipeline, code_review_crew, multi_framework, patient_portal)
- `fixtures/<framework>/` — focused single-framework fixtures (langgraph_research_agent, openai_agents_triage, crewai_blog_team, llamaindex_rag)

`tests/smoke/` — end-to-end tests requiring network + git; mark-gated with `pytest -m smoke`.

## Tooling

- **Ruff**: line length 100, target Python 3.11
- **mypy**: strict mode
- **pytest**: `src/` on `pythonpath`; `-q` by default
- Optional extras: `ts` (tree-sitter), `cdx` (cyclonedx-bom), `llm` (litellm)
