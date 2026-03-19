# GitHub Copilot — Workspace Instructions

The canonical guide for this repository is [CLAUDE.md](../CLAUDE.md) in the root.
Read it before making any changes. Key sections:

- **Package identity & CLI entry points** — package is `xelo`, CLI is `xelo` / `ai-sbom`
- **Commands** — install, lint (`ruff`), type-check (`mypy`), test (`pytest`), CLI usage
- **Architecture** — extraction pipeline, adapter types, plugin system, data model, output formats
- **Configuration** — `AiSbomConfig`, environment variables, LLM routing
- **Toolbox** — plugin base class, available plugins, benchmark utilities
- **Test fixtures** — fixture layout, smoke test guard (`pytest -m "not smoke"`)
- **Schema regeneration** — must run after any change to `src/xelo/models.py`
- **Tooling** — Ruff (line length 100, Python 3.11), mypy strict, pytest with `src/` on `pythonpath`

## Quick reminders

- Next available structural rule ID: **XELO-006**
- After editing `models.py`, regenerate `src/xelo/schemas/aibom.schema.json` (command in CLAUDE.md)
- New adapters go in `adapters/python/` (Python) or `adapters/typescript/` (TS/JS)
- New toolbox plugins go in `src/xelo/toolbox/plugins/`
- Do not edit files in `tests/test_toolbox/fixtures/` — they are ground-truth benchmark data
