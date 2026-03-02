# Troubleshooting

Use this guide to diagnose and fix common Xelo CLI issues.

## Quick Diagnosis

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `error: path not found: ...` | Scan target path does not exist | Verify path and rerun `xelo scan path <existing-dir> ...` |
| `error: not a directory: ...` | Provided path points to file, not directory | Use a directory path for `scan path` |
| `error: file not found: ...` (validate) | Input JSON file missing | Confirm output location and filename |
| `error: not valid JSON: ...` | Corrupted or non-JSON file passed to `validate` | Regenerate output or inspect JSON syntax |
| `error: validation failed: ...` | JSON doesn\'t match `AiBomDocument` schema | Regenerate with Xelo or fix required fields |
| `error: cannot write output file: ...` | Missing permissions / invalid output path | Use writable directory and check permissions |
| `error: I/O error writing ...` | Filesystem or path issue | Check disk/path validity and retry |
| Unified mode output is shallow | `cyclonedx-py` unavailable so fallback used | Install optional dependency: `pip install "xelo[cdx]"` |
| LLM enrichment fails to start | Missing `litellm` or provider credentials | Install `pip install "xelo[llm]"` and set provider env vars |
| `scan repo` fails early | `git` missing on PATH, bad URL, or bad ref | Install git, verify repo URL, and verify `--ref` |

## Logging Levels

- Use `--verbose` for scan progress and useful runtime context.
- Use `--debug` for deep diagnostics and full traceback output.

Examples:

```bash
xelo --verbose scan path ./my-repo --output sbom.json
xelo --debug validate sbom.json
```

## Common Remediation Flows

Regenerate and validate:

```bash
xelo scan path ./my-repo --format json --output sbom.json
xelo validate sbom.json
```

Check command usage:

```bash
xelo --help
xelo scan --help
xelo scan path --help
```

Retry unified scan:

```bash
xelo scan path ./my-repo --format unified --output unified-bom.json
```

## Safe Support Bundle

When reporting an issue, include:

- Exact command run
- Full stderr/stdout output
- Xelo version (`pip show xelo`)
- Python version (`python --version`)
- OS details

Before sharing logs or `.env` snippets:

- Remove `AISBOM_LLM_API_KEY` and any provider API keys
- Remove internal URLs/tokens/secrets

## Escalation

- General support: [SUPPORT.md](../SUPPORT.md)
- Sensitive/security issues: [SECURITY.md](../SECURITY.md)
