# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Xelo is an AI SBOM generator for agentic and LLM-powered applications. The project is security-centric by design — prefer deterministic extraction, explicit evidence, strict validation, and small reviewable changes.

## Package identity

The Python package is `xelo` (under `src/xelo/`). CLI entry points: `xelo` (primary) and `ai-sbom` (legacy alias), both pointing to `xelo.cli:main`. The PyPI distribution name is `xelo`.

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

## Working style

- Keep changes focused. One logical behavior change per edit set.
- Preserve the existing documentation tone: concise, direct, and operational.
- Default to Python 3.11-compatible code.
- Match existing style constraints: Ruff line length 100, `mypy` strict mode, Pydantic v2 models and typed APIs.
- Prefer extending existing adapters, models, and serializers over introducing parallel abstractions.
- Avoid speculative refactors unless they are required to complete the task safely.

## Security expectations

- Treat all inputs as untrusted: repository paths, remote repository URLs, config files, prompt files, manifests, and plugin config.
- Do not log, commit, or echo secrets, tokens, credentials, or private data.
- Preserve deterministic defaults. LLM enrichment must remain opt-in.
- Prefer offline, auditable behavior over network-dependent behavior unless the task explicitly requires network access.
- For security-sensitive changes, verify failure modes as carefully as success paths.
- Do not weaken validation, schema guarantees, or evidence tracking without an explicit reason and corresponding tests.

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
- `nodes: list[Node]` — detected AI components (`ComponentType` enum in `types.py`); each `Node` embeds `evidence: list[Evidence]`
- `edges: list[Edge]` — directed relationships (`RelationshipType` enum)
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

First-party post-processing plugins. Infrastructure modules:
- `plugin_base.py` — `ToolboxPlugin` base class
- `core.py` — shared helpers
- `models.py` — toolbox-specific Pydantic models
- `integration_contracts.py` — typed contracts for external integrations
- `grype_client.py`, `osv_client.py` — vulnerability feed clients
- `http_utils.py` — shared HTTP helpers

Plugins live in `src/xelo/toolbox/plugins/` (13 files):

| Plugin | Purpose |
| --- | --- |
| `cyclonedx_exporter.py` | Export nodes as CycloneDX 1.6 BOM |
| `sarif_exporter.py` | Export findings as SARIF |
| `markdown_exporter.py` | Human-readable Markdown report |
| `vulnerability.py` | Dependency CVE lookup via Grype/OSV |
| `dependency.py` | Dependency graph analysis |
| `license_checker.py` | SPDX license compliance |
| `atlas_annotator.py` | Atlas security annotation |
| `aws_security_hub.py` | Upload findings to AWS Security Hub |
| `ghas_uploader.py` | Upload SARIF to GitHub Advanced Security |
| `xray.py` | JFrog Xray integration |

Benchmark and evaluation utilities live in `tests/test_toolbox/` and are **not** part of the installed package:

```python
# Run directly from the tests directory
from tests.test_toolbox.evaluate import evaluate_discovery
from tests.test_toolbox.evaluate_risk import evaluate_risk_assessment
```

### Test fixtures

`tests/fixtures/` contains realistic AI application code used by `test_extraction.py`:
- `fixtures/apps/` — multi-file scenario apps (customer_service_bot, research_assistant, rag_pipeline, code_review_crew, multi_framework, patient_portal)
- `fixtures/<framework>/` — focused single-framework fixtures (langgraph_research_agent, openai_agents_triage, crewai_blog_team, llamaindex_rag)

`tests/test_toolbox/` — benchmark evaluation utilities, integration tests, and ground-truth datasets:
- `evaluate.py`, `evaluate_risk.py` — benchmark runner scripts
- `evaluate_streaming.py` — streaming evaluation runner
- `schemas.py`, `schemas_risk.py` — Pydantic models for evaluation results
- `fetcher.py` — GitHub repository fetching for live benchmark runs
- `test_basic.py` — offline plugin smoke tests (run with `pytest tests/test_toolbox/test_basic.py`)
- `fixtures/` — cached repo snapshots with `ground_truth.json` and `risk_ground_truth.json` per repo

`tests/smoke/` — end-to-end tests requiring network + git; mark-gated with `pytest -m smoke`.

## Documentation

User-facing docs live in `docs/`:

| File | Content |
| --- | --- |
| `docs/getting-started.md` | Install, first scan, LLM enrichment, supported frameworks |
| `docs/aibom-schema.md` | Every field — node types, metadata, evidence, edges, data classification, ScanSummary |
| `docs/cli-reference.md` | Full command and flag matrix |
| `docs/developer-guide.md` | Python library API, toolbox plugins, provider config examples |
| `docs/troubleshooting.md` | Common errors and remediation |
| `docs/CHANGELOG.md` | User-facing docs changes per release |

## Tooling

- **Ruff**: line length 100, target Python 3.11
- **mypy**: strict mode
- **pytest**: `src/` on `pythonpath`; `-q` by default
- Optional extras: `toolbox` (python-dotenv + httpx), `llm` (litellm), `ts` (tree-sitter), `cdx` (cyclonedx-bom)

## Schema regeneration

Run this after any change to `src/xelo/models.py`:

```bash
python -c "
import json; from xelo.models import AiSbomDocument
schema = AiSbomDocument.model_json_schema()
schema['\$id'] = 'https://nuguard.ai/schemas/aibom/1.1.0/aibom.schema.json'
schema['\$schema'] = 'https://json-schema.org/draft/2020-12/schema'
with open('src/xelo/schemas/aibom.schema.json','w') as f: json.dump(schema,f,indent=2); f.write('\n')
"
```

## Change guidance

- New framework support should usually land as an adapter plus focused fixture coverage.
- Changes to `src/xelo/models.py` or output structure should include schema and serialization validation.
- CLI changes should keep defaults stable and help text explicit.
- Plugin changes should document network requirements, credentials, and output contracts.
- Detection improvements should favor high-confidence evidence and avoid broad regexes that inflate false positives.
- If behavior changes are user-visible, update the relevant documentation in `README.md` or `docs/`.

## Testing expectations

- Add or update tests for every behavior change.
- Prefer the smallest fixture or test file that proves the behavior.
- When fixing false positives or false negatives, add a regression test that would have failed before the change.
- Do not edit files in `tests/test_toolbox/fixtures/` — they are ground-truth benchmark data.
- If you cannot run a relevant validation command, state that clearly in your handoff.

## Notes

- `AGENTS.md` and `CLAUDE.md` are intentionally skipped by the extractor and will not affect scan output.
- Do not edit generated artifacts or release files unless the task requires it.
- Do not remove unrelated user changes from the working tree.
