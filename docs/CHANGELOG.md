# Documentation Changelog

Track user-facing documentation updates here, especially changes to CLI behavior, workflows, and troubleshooting guidance.

## v0.1.5 - 2026-03-06

### Added
- **Granular PRIVILEGE detection**: 8 per-category privilege adapters (`rbac`, `admin`, `filesystem_write`, `db_write`, `email_out`, `social_media_out`, `code_execution`, `network_out`) replacing a single coarse detector.
- **MCP Server adapter enrichment**: auth patterns, API endpoints, and LLM-generated descriptions for MCP tool nodes.
- **Kendra and S3 datastore detection**: `amazon-kendra` keyword and `boto3.client/resource('s3')` patterns added to the datastore regex adapter.
- **LangChain Bedrock support**: Legacy `Bedrock`/`BedrockLLM` LangChain LLM classes now detected; `model_id`/`modelId` kwargs extracted for Bedrock model names.
- **Bedrock `invoke_model` support**: `invoke_model`, `invoke_model_with_response_stream`, and `converse` added as model-specifying API call methods.

### Fixed
- Privilege adapters now skip `tests/`, `test/`, `e2e/`, and `__init__.py` files to eliminate test-infrastructure false positives (~50 FPs removed).
- `db_write` SQL patterns require a following identifier, preventing `CREATE Table` titles from matching.
- `filesystem_write` now correctly detects `wb.save()`, `workbook.save()`, `df.to_excel()`, and `writer.save()` in addition to `open(..., 'w')`.

### Changed
- Overall benchmark F1 improved from 85.75% → 87.76%.
- `bedrock-langchain-agent` benchmark F1 improved from 50% → 85.71%.

## Unreleased

### Added

- Framework support expanded to cover Google ADK, AWS BedrockAgentCore, Agno (Python + TypeScript), Azure AI Agent Service (Python + TypeScript), MCP Server (Python + TypeScript), OpenAI Agents SDK, LangChain.js, LangGraph.js, and OpenAI Agents (TypeScript).
- CrewAI and AutoGen YAML config files (`agents.yaml`, OAI_CONFIG_LIST, autogen_ext provider configs) are now scanned as additional detection sources.
- Dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`) are now discovered recursively at any depth in the project tree. Previously only root-level manifests were scanned. Excludes `.venv`, `node_modules`, `dist`, `build`, `.git`, and similar directories.
- `docs/cli-reference.md`: Added **Detected Component Types** table listing all `component_type` values in output JSON.
- `docs/developer-guide.md`: Added **Inspect Extracted Data** section documenting `doc.nodes`, `doc.edges`, `doc.deps`, and `doc.summary` fields.
- `docs/developer-guide.md`: Added **Supported Frameworks** list.
- `docs/getting-started.md`: Added **Understanding Scan Output** section describing all top-level output fields.
- `docs/getting-started.md`: Added **Supported Frameworks** list.
- `docs/troubleshooting.md`: Added `deps: []` and `summary.frameworks: []` diagnostic entries.

### Changed

- `summary.frameworks` now correctly populates for all supported frameworks including those whose internal adapter names use underscores (e.g. `openai_agents`, `google_adk`). Previously these were silently omitted.
- README: Added **Supported Frameworks** section. Fixed two "DeXelopment" typos.

### Fixed

- Fixed `deps: []` in scan output when package manifest files are located in subdirectories rather than the repository root (e.g. `python-backend/requirements.txt`, `backend/pyproject.toml`).
- Fixed `summary.frameworks: []` when detected framework names used underscore separators instead of hyphens.

## Release Template

Use this format when cutting a release:

```md
## vX.Y.Z - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...

### Removed
- ...
```

## Update Checklist

1. Update this file for any user-visible docs change.
2. Ensure [CLI Reference](./cli-reference.md) matches current argparse flags/defaults.
3. Ensure [Getting Started](./getting-started.md) commands still run as documented.
4. Ensure troubleshooting entries still match real error messages.
