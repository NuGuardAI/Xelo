# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Package identity

The Python package is `xelo` (under `src/xelo/`). The sole CLI entry point is `xelo` (pointing to `xelo.cli:main`). The PyPI distribution name is `xelo`.

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
xelo scan ./my-repo --format json --output sbom.json
xelo scan https://github.com/org/repo --ref main --output sbom.json
xelo validate sbom.json
xelo schema
```

## Architecture

### Extraction pipeline (`src/xelo/extractor.py`)

`AiSbomExtractor` orchestrates a 3-phase pipeline over every file in the target directory:

1. **Phase 1 — AST-aware adapters** (language-specific):
   - Python (`.py`, `.ipynb`): Python `ast` via `ast_parser.parse()` → `FrameworkAdapter.extract()`
   - TypeScript/JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`): tree-sitter (or regex fallback) via `core/ts_parser.py` → `TSFrameworkAdapter.extract()`
   - SQL (`.sql`): `DataClassificationSQLAdapter.scan()`
   - Dockerfiles: `DockerfileAdapter.scan()`

2. **Phase 2 — Regex fallbacks**: `RegexAdapter.detect()` runs on all files for non-framework signals (model names, datastores, auth keywords, etc.).

3. **Phase 3 — LLM enrichment** (optional, `AiSbomConfig(enable_llm=True)`): verifies uncertain nodes, re-aggregates confidence scores, refines use-case summary via `litellm`.

Results deduplicate on `(ComponentType, canonical_name)` and assemble into `AiSbomDocument`.

### Adapter types (`src/xelo/adapters/base.py`)

Two distinct adapter hierarchies:
- **`DetectionAdapter` / `RegexAdapter`** — legacy regex-only, returns `AdapterDetection`
- **`FrameworkAdapter`** — AST-aware, receives a `ParseResult`, returns `list[ComponentDetection]`; Python adapters live in `adapters/python/`, TypeScript adapters in `adapters/typescript/`

`FrameworkAdapter.can_handle(imports)` gates execution; adapters declare `handles_imports` (module name prefixes). Lower `priority` integer = higher precedence during dedup.

### Plugin system (`src/xelo/plugins/`)

Third-party plugins subclass `PluginAdapter` (in `plugins/base.py`). They are opt-in:

```python
extractor = AiSbomExtractor(load_plugins=True)
```

Or call `xelo.plugins.load_plugins()` directly. Discovery uses Python entry-points under the `xelo.plugins` group plus any sub-modules inside `xelo.plugins`.

### Core data model (`src/xelo/models.py`)

All types are Pydantic v2 `BaseModel`. The `AiSbomDocument` is the root output:
- `nodes: list[Node]` — detected AI components (`ComponentType` enum in `types.py`)
- `edges: list[Edge]` — directed relationships (`RelationshipType` enum)
- `evidence: list[Evidence]` — detection evidence per node
- `deps: list[PackageDep]` — package manifest dependencies
- `summary: ScanSummary` — deterministic scan-level metadata (frameworks, modalities, deployment info, data classification)

The JSON schema is generated directly from `AiSbomDocument.model_json_schema()`.

### Output formats

`AiSbomSerializer` (serializer.py) handles:
- `json` — Xelo-native `AiSbomDocument` JSON
- `cyclonedx` — AI components only, CycloneDX 1.6
- `unified` — standard deps BOM (via `cyclonedx-bom` CLI or supplied file) merged with AI-BOM via `AiBomMerger` (merger.py)

### Key configuration (`src/xelo/config.py`)

`AiSbomConfig` defaults to `enable_llm=False`. LLM enrichment requires `--llm` flag or `XELO_LLM=true`. LLM calls go through `litellm` (`llm_client.py`).

Environment variables:

| Variable                | Purpose                                      | Default        |
|-------------------------|----------------------------------------------|----------------|
| `XELO_LLM`              | Enable LLM enrichment (`true`/`1`)           | `false`        |
| `XELO_LLM_MODEL`        | LLM model passed to litellm                  | `gpt-4o-mini`  |
| `XELO_LLM_API_KEY`      | API key for LLM provider                     | —              |
| `XELO_LLM_API_BASE`     | Base URL for LLM provider                    | —              |
| `XELO_LLM_BUDGET_TOKENS`| Max tokens to spend on enrichment            | `50000`        |

Legacy `AISBOM_*` names are accepted as fallbacks.

### Toolbox (`src/xelo/toolbox/`)

Reserved for first-party plugin adapter implementations (currently a placeholder — plugins from xelo-toolbox have not yet been ported).

Benchmark and evaluation utilities live in `tests/test_toolbox/` and are **not** part of the installed package:

```python
# Run directly from the tests directory
from tests.test_toolbox.evaluate import evaluate_discovery
from tests.test_toolbox.evaluate_risk import evaluate_risk_assessment
from tests.test_toolbox.evaluate_policies import run_policy_benchmark
```

### Test fixtures

`tests/fixtures/` contains realistic AI application code used by `test_extraction.py`:
- `fixtures/apps/` — multi-file scenario apps (customer_service_bot, research_assistant, rag_pipeline, code_review_crew, multi_framework, patient_portal)
- `fixtures/<framework>/` — focused single-framework fixtures (langgraph_research_agent, openai_agents_triage, crewai_blog_team, llamaindex_rag)

`tests/test_toolbox/` — benchmark evaluation utilities and ground-truth datasets:
- `evaluate.py`, `evaluate_risk.py`, `evaluate_policies.py` — runner scripts
- `schemas.py`, `schemas_risk.py` — Pydantic models for evaluation results
- `fetcher.py` — GitHub repository fetching for live benchmark runs
- `policies/`, `policies_ccd/` — policy definitions (OWASP AI Top 10, HIPAA, etc.)
- `policy_ground_truth/` — expected policy evaluation results per repo
- `fixtures/` — cached repo snapshots with `ground_truth.json` and `risk_ground_truth.json` per repo

`tests/smoke/` — end-to-end tests requiring network + git; mark-gated with `pytest -m smoke`.

## Tooling

- **Ruff**: line length 100, target Python 3.11
- **mypy**: strict mode
- **pytest**: `src/` on `pythonpath`; `-q` by default
- Optional extras: `toolbox` (python-dotenv + httpx), `llm` (litellm), `ts` (tree-sitter), `cdx` (cyclonedx-bom)
