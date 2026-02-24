# Vela

Deterministic AI SBOM generator with embedded schema models.

## Features
- Extract AI stack components from Python/TypeScript/config files.
- Emit native AI-BOM JSON and CycloneDX-compatible JSON.
- Validate documents against strict Pydantic models.
- Export JSON schema from the same package.

## Quickstart
```bash
pip install -e .
velo scan path ./my-repo --format json --output sbom.json
velo validate sbom.json
velo schema --output ai_bom.schema.json
```

Backward-compatible CLI alias: `ai-sbom`.

## Public API
- `SbomExtractor.extract_from_path(path, config) -> AiBomDocument`
- `SbomExtractor.extract_from_repo(url, ref, config) -> AiBomDocument`
- `SbomSerializer.to_json(doc) -> str`
- `SbomSerializer.to_cyclonedx(doc, spec_version="1.6") -> dict`

## Security Model
- Deterministic parsing by default.
- No outbound network calls during path scan.
- Bounded file size and count.
- LLM augmentation intentionally omitted in v0.1.0.
