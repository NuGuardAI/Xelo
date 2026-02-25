# Velo

Deterministic AI SBOM generator with embedded schema models.

## Features
- Extract AI stack components from Python/TypeScript/config files.
- Emit native AI-BOM JSON and CycloneDX-compatible JSON.
- Validate documents against strict Pydantic models.
- Export JSON schema from the same package.

## Quickstart
```bash
pip install xelo
velo scan path ./my-repo --format json --output sbom.json
velo validate sbom.json
velo schema --output ai_bom.schema.json
```

Backward-compatible CLI alias: `ai-sbom`.

## Run Tests
```bash
pip install -e ".[dev]"
pytest
```

Optional coverage run:
```bash
pytest --cov=ai_sbom --cov-report=term-missing
```

## LLM Enrichment Controls
`velo scan` can be configured through `.env` and CLI flags.

- `.env` keys:
  - `AISBOM_DETERMINISTIC_ONLY=true|false`
  - `AISBOM_LLM_MODEL=<litellm model string>`
  - `AISBOM_LLM_BUDGET_TOKENS=<int>`
  - `AISBOM_LLM_API_KEY=<optional key>`
- CLI flags (take precedence over `.env`):
  - `--deterministic-only`
  - `--enable-llm`
  - `--llm-model <model>`
  - `--llm-budget-tokens <n>`
  - `--llm-api-key <key>`

Example:
```bash
velo scan path ./my-repo --enable-llm --llm-model gpt-4o-mini --output sbom.json
```

## Public API
- `SbomExtractor.extract_from_path(path, config) -> AiBomDocument`
- `SbomExtractor.extract_from_repo(url, ref, config) -> AiBomDocument`
- `SbomSerializer.to_json(doc) -> str`
- `SbomSerializer.to_cyclonedx(doc, spec_version="1.6") -> dict`

## Security Model
- Deterministic parsing by default.
- No outbound network calls during path scan.
- Bounded file size and count.
- Optional LLM enrichment is disabled by default and can be explicitly enabled.

## Publish To PyPI (Manual)
Build release artifacts:
```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

Upload to PyPI:
```bash
python -m twine upload dist/*
```

Use API token auth when prompted:
- Username: `__token__`
- Password: `<your PyPI API token>`

Expected artifacts for this project:
- `dist/ng_aibom-0.1.0.tar.gz`
- `dist/ng_aibom-0.1.0-py3-none-any.whl`
