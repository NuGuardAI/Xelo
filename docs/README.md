# Xelo Documentation

This documentation set explains how to install, run, and develop Xelo, an open-source AI SBOM generator for agentic and LLM-powered applications.

## Start Here

1. Install Xelo and verify prerequisites in [Getting Started](./getting-started.md).
2. Run your first local scan.
3. Use [CLI Reference](./cli-reference.md) for all command and flag details.

## Guides

| Guide | Audience | What it covers |
| --- | --- | --- |
| [Getting Started](./getting-started.md) | End users | Install, first scan, understanding output fields, supported frameworks, env basics |
| [CLI Reference](./cli-reference.md) | End users / operators | Full command and flag matrix for `xelo` and `ai-sbom` |
| [Developer Guide](./developer-guide.md) | Application developers | Python library API, `AiSbomExtractor`, `AiSbomConfig`, `doc.deps`, `doc.summary`, provider config examples |
| [Troubleshooting](./troubleshooting.md) | End users / contributors | Common errors, diagnostics, and remediation steps |
| [Documentation Changelog](./CHANGELOG.md) | Maintainers / contributors | Track user-facing docs changes per release |

## Version and Compatibility

- Package: `xelo` version `0.1.2`
- Python: `>=3.11`
- CLI entry points: `xelo`, `ai-sbom`

Values above are sourced from `pyproject.toml`.
