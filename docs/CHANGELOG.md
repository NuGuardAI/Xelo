# Documentation Changelog

Track user-facing documentation updates here, especially changes to CLI behavior, workflows, and troubleshooting guidance.

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
