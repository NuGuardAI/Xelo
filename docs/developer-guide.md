<img src="xelo-logo.png" alt="Xelo" height="20" />

# Developer Guide

This guide covers using Xelo as a Python library: extracting AI SBOM data, inspecting results, running toolbox plugins, and serialising output.

## Install

```bash
pip install xelo
```

## Core API

```python
from xelo import AiSbomConfig, AiSbomExtractor, AiSbomSerializer
```

- `AiSbomExtractor` — runs the extraction pipeline on a local path or git repository
- `AiSbomConfig` — controls scan scope and enrichment; deterministic by default
- `AiSbomSerializer` — converts an `AiSbomDocument` to Xelo JSON or CycloneDX

## Extract From a Local Path

```python
from pathlib import Path
from xelo import AiSbomConfig, AiSbomExtractor

doc = AiSbomExtractor().extract_from_path(
    path=Path("./my-repo"),
    config=AiSbomConfig(),
)
print(f"nodes={len(doc.nodes)}  edges={len(doc.edges)}")
```

## Extract From a Remote Repository

```python
from xelo import AiSbomConfig, AiSbomExtractor, AiSbomSerializer

doc = AiSbomExtractor().extract_from_repo(
    url="https://github.com/example/project.git",
    ref="main",
    config=AiSbomConfig(),
)
Path("sbom.json").write_text(AiSbomSerializer.to_json(doc), encoding="utf-8")
```

`extract_from_repo` requires `git` on `PATH`.

## Enable LLM Enrichment

```python
from xelo import AiSbomConfig

config = AiSbomConfig(
    enable_llm=True,
    llm_model="gpt-4o-mini",        # any litellm model string
    llm_budget_tokens=50_000,       # hard token cap
)
```

Set the API key in the environment (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, etc.) or pass `llm_api_key="..."` to `AiSbomConfig`.

**Provider examples:**

```python
# Anthropic
AiSbomConfig(enable_llm=True, llm_model="anthropic/claude-3-5-sonnet-latest")

# Google Gemini
AiSbomConfig(enable_llm=True, llm_model="gemini/gemini-2.0-flash")

# AWS Bedrock
AiSbomConfig(enable_llm=True, llm_model="bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0")

# Azure OpenAI
AiSbomConfig(enable_llm=True, llm_model="azure/gpt-4o-mini",
             llm_api_key="...", llm_api_base="https://<resource>.openai.azure.com/")
```

## Inspect the Document

```python
# Component nodes
for node in doc.nodes:
    print(node.component_type, node.name, node.confidence)
    # Typed metadata fields
    if node.metadata.model_name:
        print("  model:", node.metadata.model_name)
    if node.metadata.datastore_type:
        print("  datastore:", node.metadata.datastore_type)
    if node.metadata.classified_tables:
        print("  pii/phi tables:", node.metadata.classified_tables)
    if node.metadata.privilege_scope:
        print("  privilege:", node.metadata.privilege_scope)

# Relationships
for edge in doc.edges:
    print(edge.source, "→", edge.relationship_type, "→", edge.target)

# Package dependencies (scanned recursively at any depth)
for dep in doc.deps:
    print(dep.name, dep.version_spec, dep.purl)

# Scan summary
print(doc.summary.use_case)
print(doc.summary.frameworks)
print(doc.summary.data_classification)  # e.g. ['PHI', 'PII']
print(doc.summary.classified_tables)    # tables carrying PII/PHI
```

## Serialise Output

```python
from xelo import AiSbomSerializer

# Xelo-native JSON (schema v1.1.0)
json_text = AiSbomSerializer.to_json(doc)

# CycloneDX 1.6 JSON string
cdx_text = AiSbomSerializer.dump_cyclonedx_json(doc)

# CycloneDX as a Python dict
cdx_dict = AiSbomSerializer.to_cyclonedx(doc)
```

## Toolbox Plugins

Xelo ships with analysis plugins in `xelo.toolbox.plugins`. They can be run from the CLI with `xelo plugin run`, or called directly from Python.

**CLI (recommended for simple use cases):**

```bash
xelo plugin list                                        # show all plugins
xelo plugin run vulnerability sbom.json                 # VLA rules to stdout
xelo plugin run sarif sbom.json --output results.sarif  # SARIF export
xelo plugin run markdown sbom.json --output report.md   # Markdown report
xelo plugin run policy sbom.json \
  --config policy_file=owasp.json \
  --config llm_model=gpt-4o
```

**Python API (for pipeline integration or chaining):**

Each plugin takes an SBOM dict and a config dict, and returns a `ToolResult` with `status`, `message`, and `details`.

```python
from xelo.toolbox.plugins.vulnerability import VulnerabilityScannerPlugin
from xelo.toolbox.plugins.atlas_annotator import AtlasAnnotatorPlugin
from xelo.toolbox.plugins.sarif_exporter import SarifExporterPlugin
from xelo.toolbox.plugins.markdown_exporter import MarkdownExporterPlugin
from xelo.toolbox.plugins.policy_assessment import PolicyAssessmentPlugin

sbom = doc.model_dump(mode="json")

# Structural vulnerability rules (offline)
vuln = VulnerabilityScannerPlugin().run(sbom, {})
print(vuln.status, vuln.message)
for f in vuln.details["findings"]:
    print(f["rule_id"], f["severity"], f["title"])

# MITRE ATLAS annotation (offline)
atlas = AtlasAnnotatorPlugin().run(sbom, {})
for f in atlas.details["findings"]:
    for t in f["atlas"]["techniques"]:
        print(t["technique_id"], t["tactic_name"], t["confidence"])

# Policy assessment against a custom policy file
policy = PolicyAssessmentPlugin().run(sbom, {"policy_file": "owasp_ai_top10.json"})
print(policy.status, policy.message)

# SARIF export (for GitHub Code Scanning upload)
# ToolResult.details IS the SARIF 2.1.0 dict
sarif = SarifExporterPlugin().run(sbom, {})
Path("results.sarif").write_text(
    json.dumps(sarif.details, indent=2), encoding="utf-8"
)

# Markdown report
md = MarkdownExporterPlugin().run(sbom, {})
Path("report.md").write_text(md.details["markdown"], encoding="utf-8")
```

`ToolResult` fields:

| Field | Type | Description |
| --- | --- | --- |
| `status` | `"ok"` \| `"error"` \| `"warning"` | Outcome of the run |
| `message` | str | One-line human-readable summary |
| `details` | dict | Plugin-specific payload (findings list, `markdown` string, SARIF dict, …) |

### Available Plugins

| Class | Module | Network | Notes |
| --- | --- | --- | --- |
| `VulnerabilityScannerPlugin` | `vulnerability` | No | Offline, no network |
| `AtlasAnnotatorPlugin` | `atlas_annotator` | No | Offline; runs VLA pass + native graph checks |
| `PolicyAssessmentPlugin` | `policy_assessment` | No | Requires `policy_file` in config |
| `LicenseCheckerPlugin` | `license_checker` | No | Offline |
| `DependencyAnalyzerPlugin` | `dependency` | No | Offline |
| `SarifExporterPlugin` | `sarif_exporter` | No | Offline |
| `CycloneDxExporter` | `cyclonedx_exporter` | No | Offline |
| `MarkdownExporterPlugin` | `markdown_exporter` | No | Offline |
| `GhasUploaderPlugin` | `ghas_uploader` | Yes | Requires `GITHUB_TOKEN` env var |
| `AwsSecurityHubPlugin` | `aws_security_hub` | Yes | Requires `boto3` + AWS credentials |
| `XrayPlugin` | `xray` | Yes | Requires JFrog Xray URL + credentials |

All plugin classes are importable from `xelo.toolbox.plugins.<module>`.

### Third-Party Detection Adapters (xelo.plugins)

To extend *detection* (adding support for a new framework), subclass `xelo.plugins.PluginAdapter` and register it under the `xelo.plugins` entry-point group:

```toml
# pyproject.toml — in your third-party package
[project.entry-points."xelo.plugins"]
my_adapter = "my_package.adapter:MyAdapter"
```

Enable discovery at extraction time:

```python
from xelo import AiSbomExtractor, AiSbomConfig

# Discovers all installed entry-point plugins + xelo.plugins sub-modules
extractor = AiSbomExtractor(load_plugins=True)
doc = extractor.extract_from_path("./my-repo", config=AiSbomConfig())
```

Or load plugins manually before constructing the extractor:

```python
from xelo.plugins import load_plugins
load_plugins()  # imports all plugin adapters, registering subclasses

from xelo import AiSbomExtractor
extractor = AiSbomExtractor(load_plugins=True)
```

## End-to-End Example

```python
from pathlib import Path
from xelo import AiSbomConfig, AiSbomExtractor, AiSbomSerializer
from xelo.toolbox.plugins.vulnerability import VulnerabilityScannerPlugin
from xelo.toolbox.plugins.atlas_annotator import AtlasAnnotatorPlugin

# 1. Extract
doc = AiSbomExtractor().extract_from_repo(
    url="https://github.com/example/project.git",
    ref="main",
    config=AiSbomConfig(enable_llm=True, llm_model="gpt-4o-mini"),
)

# 2. Save SBOM
Path("ai-sbom.json").write_text(AiSbomSerializer.to_json(doc), encoding="utf-8")

# 3. Analyse
sbom = doc.model_dump(mode="json")
vuln = VulnerabilityScannerPlugin().run(sbom, {})
atlas = AtlasAnnotatorPlugin().run(sbom, {})
print(f"{vuln.message}  |  {atlas.message}")
```

## Notes

- Extraction is thread-safe; you can run multiple `AiSbomExtractor` instances concurrently.
- If LLM enrichment fails, extraction still returns the full deterministic result.
- Very large repositories: tune `max_files` and `max_file_size_bytes` in `AiSbomConfig`.
- For CLI usage see [CLI Reference](./cli-reference.md).
- For the schema spec see [AI SBOM Schema](./aibom-schema.md).
