# AGENTS.md

This file provides guidance to coding agents working in this repository.

## Project identity

Xelo is an AI SBOM generator for agentic and LLM-powered applications. The Python package is `xelo` under `src/xelo/`. The primary CLI entry point is `xelo`, implemented in `src/xelo/cli.py`.

The project is security-centric by design. Prefer deterministic extraction, explicit evidence, strict validation, and small reviewable changes.

## Working style

- Keep changes focused. One logical behavior change per edit set.
- Preserve the existing documentation tone: concise, direct, and operational.
- Default to Python 3.11-compatible code.
- Match existing style constraints:
  - Ruff line length: 100
  - `mypy` strict mode
  - Pydantic v2 models and typed APIs
- Prefer extending existing adapters, models, and serializers over introducing parallel abstractions.
- Avoid speculative refactors unless they are required to complete the task safely.

## Security expectations

- Treat all inputs as untrusted: repository paths, remote repository URLs, config files, prompt files, manifests, and plugin config.
- Do not log, commit, or echo secrets, tokens, credentials, or private data.
- Preserve deterministic defaults. LLM enrichment must remain opt-in.
- Prefer offline, auditable behavior over network-dependent behavior unless the task explicitly requires network access.
- For security-sensitive changes, verify failure modes as carefully as success paths.
- Do not weaken validation, schema guarantees, or evidence tracking without an explicit reason and corresponding tests.

## Repository workflow

Use these commands for local validation:

```bash
pip install -e ".[dev]"
ruff check src tests
mypy src
pytest
pytest -m "not smoke"
```

Useful targeted commands:

```bash
pytest tests/test_extraction.py
pytest tests/test_cli.py
pytest tests/test_toolbox/test_basic.py
python -m tests.test_toolbox.evaluate --all --mode local --verbose
```

If behavior changes are user-visible, update the relevant documentation in `README.md` or `docs/`.

## Codebase map

- `src/xelo/extractor.py`: main extraction pipeline
- `src/xelo/adapters/python/`: Python framework adapters
- `src/xelo/adapters/typescript/`: TypeScript and JavaScript framework adapters
- `src/xelo/adapters/`: shared detection, registry, Dockerfile, IaC, nginx, and classification logic
- `src/xelo/toolbox/`: post-processing and integration plugins
- `src/xelo/models.py`: core SBOM document models
- `src/xelo/config.py`: scan configuration and LLM settings
- `src/xelo/serializer.py`: JSON and CycloneDX serialization
- `tests/`: unit, integration, smoke, and fixture-backed extraction coverage

## Change guidance

- New framework support should usually land as an adapter plus focused fixture coverage.
- Changes to `src/xelo/models.py` or output structure should include schema and serialization validation.
- CLI changes should keep defaults stable and help text explicit.
- Plugin changes should document network requirements, credentials, and output contracts.
- Detection improvements should favor high-confidence evidence and avoid broad regexes that inflate false positives.

## Testing expectations

- Add or update tests for every behavior change.
- Prefer the smallest fixture or test file that proves the behavior.
- When fixing false positives or false negatives, add a regression test that would have failed before the change.
- If you cannot run a relevant validation command, state that clearly in your handoff.

## Agent notes

- `AGENTS.md` and `CLAUDE.md` are intentionally skipped by the extractor and will not affect scan output.
- Do not edit generated artifacts or release files unless the task requires it.
- Do not remove unrelated user changes from the working tree.
