"""Core SBOM extraction engine.

Orchestrates the extraction pipeline:

1. **AST-aware framework adapters** (Python files):
   Uses ``ast_parser.parse()`` to build structured parse data, then runs
   ``FrameworkAdapter.extract()`` to emit rich ``ComponentDetection`` objects.

2. **Regex fallback adapters** (all files):
   Runs legacy ``RegexAdapter.detect()`` on raw file content for non-Python
   files (YAML, Terraform, Dockerfiles, etc.) and as a catch-all for Python
   files that the framework adapters didn't fully cover.

3. **LLM enrichment** (optional, when ``ExtractionConfig.enable_llm=True``):
   Verifies uncertain detections, re-aggregates confidence scores with LLM
   input, and enriches the scan-level summary.

Results are deduplicated by ``(component_type, canonical_name)``,
merged by confidence/priority, and assembled into an ``AiBomDocument``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters.base import (
    ComponentDetection,
    DetectionAdapter,
    FrameworkAdapter,
    RelationshipHint,
)
from .adapters.data_classification import DataClassificationSQLAdapter
from .adapters.dockerfile import DockerfileAdapter
from .adapters.registry import default_framework_adapters, default_registry
from .adapters.yaml_adapters import AutoGenYAMLAdapter, CrewAIYAMLAdapter
from .adapters.typescript._ts_regex import TSFrameworkAdapter
from .config import ExtractionConfig
from .core.application_summary import build_scan_summary
from .core.ts_parser import TSParseResult, parse_typescript as _parse_ts_impl
from .deps import DependencyScanner
from .models import AiBomDocument, Edge, Evidence, Node, ScanSummary, SourceLocation
from .normalization import canonicalize_text
from .types import ComponentType, RelationshipType

_log = logging.getLogger(__name__)

# File extensions that warrant Python AST parsing
_PYTHON_EXTENSIONS = {".py", ".pyw"}
# SQL schema files: scanned by DataClassificationSQLAdapter
_SQL_EXTENSIONS = {".sql"}
# Jupyter notebooks: cells are extracted and parsed as Python
_NOTEBOOK_EXTENSIONS = {".ipynb"}
# TypeScript/JavaScript: tree-sitter (or regex fallback) via core/ts_parser
_TYPESCRIPT_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx"}
# Dockerfile: extensionless file named "Dockerfile" or suffixed ".dockerfile"
_DOCKERFILE_EXTENSIONS = {".dockerfile"}
_DOCKERFILE_NAMES = {"dockerfile"}  # lower-cased stem match

# ---------------------------------------------------------------------------
# Source-tier constants for dedup precedence: CODE > IAC > DOCS
# ---------------------------------------------------------------------------
_TIER_CODE = "code"
_TIER_IAC = "iac"
_TIER_DOCS = "docs"
# Lower rank number = higher precedence during dedup
_TIER_RANK: dict[str, int] = {_TIER_CODE: 0, _TIER_IAC: 1, _TIER_DOCS: 2}

_IAC_EXTENSIONS = {".tf", ".tfvars", ".hcl", ".bicep", ".yaml", ".yml", ".json"}
_DOCS_EXTENSIONS = {
    ".md",
    ".rst",
    ".txt",
    ".html",
    ".htm",
    ".adoc",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".mk",
}
_DOCS_STEMS = {
    "readme",
    "changelog",
    "license",
    "contributing",
    "makefile",
    "authors",
    "notice",
    "roadmap",
    "security",
    "support",
}


def _classify_source_tier(file_path: str, adapter_name: str, evidence_kind: str) -> str:
    """Classify a detection into one of three source tiers.

    CODE (0) > IAC (1) > DOCS (2).

    AST-derived evidence (``evidence_kind != "regex"``) is always CODE tier
    regardless of the file extension, since it came from actual program
    structure.  Regex detections are classified by file extension / adapter
    name so that the same component detected in source code can override a
    weaker mention in a README or Dockerfile.
    """
    # AST evidence always counts as code — the most authoritative source
    if evidence_kind != "regex":
        return _TIER_CODE
    # Dockerfile adapter is IaC regardless of file name
    if adapter_name == "dockerfile":
        return _TIER_IAC
    if not file_path:
        return _TIER_CODE
    p = Path(file_path)
    suffix = p.suffix.lower()
    stem = p.stem.lower()
    if suffix in _DOCS_EXTENSIONS or stem in _DOCS_STEMS:
        return _TIER_DOCS
    if suffix in _IAC_EXTENSIONS:
        return _TIER_IAC
    # Python / TypeScript / notebook files processed by regex fallback → code
    return _TIER_CODE


@dataclass
class _NodeAccumulator:
    """Accumulates detections for a single logical component during dedup.

    ``source_tiers`` records every tier ("code", "iac", "docs") that has
    contributed a detection, enabling cross-tier corroboration and ensuring
    that code-level attribution always takes precedence over IaC/docs.
    ``best_tier_rank`` tracks the rank of the highest-priority tier seen so
    far (lower number = better); used to decide whether incoming metadata
    should override or merely fill gaps in the accumulated metadata.
    """

    component_type: ComponentType
    canonical_name: str
    display_name: str
    adapter_name: str
    priority: int
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    relationships: list[RelationshipHint] = field(default_factory=list)
    # Source-tier tracking (populated by _merge_detection)
    source_tiers: set[str] = field(default_factory=set)
    best_tier_rank: int = 99  # 0=code, 1=iac, 2=docs; 99=uninitialised


class SbomExtractor:
    """Extract an AI SBOM from a local path or remote git repository.

    Parameters
    ----------
    framework_adapters:
        AST-aware adapters to run on Python files.  Defaults to all built-in
        framework adapters (LangGraph, OpenAI Agents, AutoGen, Semantic Kernel,
        CrewAI, LlamaIndex, LLMClients).
    regex_adapters:
        Regex-based fallback adapters for non-Python files.  Defaults to the
        built-in generic component detectors.
    """

    def __init__(
        self,
        framework_adapters: tuple[FrameworkAdapter, ...] | None = None,
        regex_adapters: tuple[DetectionAdapter, ...] | None = None,
        sql_adapters: tuple[DataClassificationSQLAdapter, ...] | None = None,
        dockerfile_adapter: DockerfileAdapter | None = None,
        yaml_adapters: tuple[Any, ...] | None = None,
    ) -> None:
        self.framework_adapters = (
            framework_adapters if framework_adapters is not None else default_framework_adapters()
        )
        self.regex_adapters = regex_adapters if regex_adapters is not None else default_registry()
        self.sql_adapters = (
            sql_adapters if sql_adapters is not None else (DataClassificationSQLAdapter(),)
        )
        self.dockerfile_adapter = (
            dockerfile_adapter if dockerfile_adapter is not None else DockerfileAdapter()
        )
        self.yaml_adapters = (
            yaml_adapters
            if yaml_adapters is not None
            else (CrewAIYAMLAdapter(), AutoGenYAMLAdapter())
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_path(
        self,
        path: str | Path,
        config: ExtractionConfig,
        source_ref: str | None = None,
        branch: str | None = None,
    ) -> AiBomDocument:
        """Extract an SBOM from a directory on the local filesystem."""
        root = Path(path).resolve()
        files = list(self._iter_files(root, config))
        _log.info("scanning %d files under %s", len(files), root)
        doc = AiBomDocument(target=source_ref or str(root))
        node_map: dict[tuple[ComponentType, str], _NodeAccumulator] = {}
        # Classification-only metadata from data_classification adapters (not emitted as nodes)
        _dc_metadata: list[dict] = []
        # Accumulated for Phase 3 LLM enrichment (rel_path → content)
        file_contents: dict[str, str] = {}

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                _log.warning("skipping unreadable file %s: %s", file_path, exc)
                continue

            rel_path = str(file_path.relative_to(root))
            file_contents[rel_path] = content
            suffix = file_path.suffix.lower()
            is_python = suffix in _PYTHON_EXTENSIONS
            is_notebook = suffix in _NOTEBOOK_EXTENSIONS
            is_typescript = suffix in _TYPESCRIPT_EXTENSIONS
            is_sql = suffix in _SQL_EXTENSIONS
            is_dockerfile = (
                suffix in _DOCKERFILE_EXTENSIONS or file_path.name.lower() in _DOCKERFILE_NAMES
            )

            # Phase 1a: Python AST-aware framework adapters
            if is_python or is_notebook:
                py_source = content
                if is_notebook:
                    py_source = self._extract_notebook_python(content)
                    if not py_source:
                        _log.debug("no code cells in notebook %s", rel_path)

                if py_source:
                    parse_result = self._parse_python(py_source)
                    if parse_result is not None:
                        if parse_result.parse_error:
                            _log.debug(
                                "AST parse error in %s: %s", rel_path, parse_result.parse_error
                            )
                        imported_modules: set[str] = {
                            imp.module for imp in parse_result.imports if imp.module
                        }
                        for adapter in self.framework_adapters:
                            # Skip TypeScript adapters for Python/notebook files
                            if isinstance(adapter, TSFrameworkAdapter):
                                continue
                            if not adapter.can_handle(imported_modules):
                                continue
                            _log.debug("running adapter %r on %s", adapter.name, rel_path)
                            try:
                                detections = adapter.extract(py_source, rel_path, parse_result)
                            except Exception as exc:
                                _log.warning(
                                    "adapter %r failed on %s: %s",
                                    adapter.name,
                                    rel_path,
                                    exc,
                                )
                                continue
                            for det in detections:
                                if (
                                    det.component_type == ComponentType.DATASTORE
                                    and det.metadata.get("source") in ("sql_schema", "python_model")
                                ):
                                    _dc_metadata.append(det.metadata)
                                else:
                                    self._merge_detection(node_map, det)

            # Phase 1b: SQL schema — data classification
            elif is_sql:
                _log.debug("running SQL data classification on %s", rel_path)
                for sql_adapter in self.sql_adapters:
                    try:
                        detections = sql_adapter.scan(content, rel_path)
                    except Exception as exc:
                        _log.warning(
                            "SQL adapter %r failed on %s: %s", sql_adapter.name, rel_path, exc
                        )
                        continue
                    for det in detections:
                        _dc_metadata.append(det.metadata)

            # Phase 1c: TypeScript/JavaScript AST-aware framework adapters
            elif is_typescript:
                ts_hints = self._parse_typescript(content, rel_path)
                imported_modules_ts: set[str] = {imp.module for imp in ts_hints.imports}
                for adapter in self.framework_adapters:
                    if not isinstance(adapter, TSFrameworkAdapter):
                        continue
                    if not adapter.can_handle(imported_modules_ts):
                        continue
                    _log.debug("running TS adapter %r on %s", adapter.name, rel_path)
                    try:
                        detections = adapter.extract(content, rel_path, ts_hints)
                    except Exception as exc:
                        _log.warning(
                            "TS adapter %r failed on %s: %s",
                            adapter.name,
                            rel_path,
                            exc,
                        )
                        continue
                    for det in detections:
                        self._merge_detection(node_map, det)

            # Phase 1d: Dockerfile — container image extraction
            if is_dockerfile:
                _log.debug("running dockerfile adapter on %s", rel_path)
                try:
                    for det in self.dockerfile_adapter.scan(content, rel_path):
                        self._merge_detection(node_map, det)
                except Exception as exc:
                    _log.warning("dockerfile adapter failed on %s: %s", rel_path, exc)

            # Phase 1e: YAML-aware framework adapters (e.g. CrewAI agents.yaml)
            if suffix in {".yaml", ".yml"}:
                for yaml_adapter in self.yaml_adapters:
                    _log.debug("running YAML adapter %r on %s", yaml_adapter.name, rel_path)
                    try:
                        for det in yaml_adapter.scan(content, rel_path):
                            self._merge_detection(node_map, det)
                    except Exception as exc:
                        _log.warning(
                            "YAML adapter %r failed on %s: %s", yaml_adapter.name, rel_path, exc
                        )

            # Phase 2: Regex fallback
            # Skip documentation and shell-script files to eliminate CI/README FP floods.
            for rx_adapter in (
                self.regex_adapters
                if suffix not in _DOCS_EXTENSIONS and Path(rel_path).stem.lower() not in _DOCS_STEMS
                else ()
            ):
                detection = rx_adapter.detect(content)
                if detection is None:
                    continue
                confidence = min(0.95, 0.50 + 0.05 * len(detection.matches))
                canonical = canonicalize_text(detection.canonical_name)
                display = (
                    detection.canonical_name.split(":")[-1]
                    if ":" in detection.canonical_name
                    else detection.canonical_name
                )
                first = detection.matches[0]
                comp_det = ComponentDetection(
                    component_type=detection.component_type,
                    canonical_name=canonical,
                    display_name=display,
                    adapter_name=detection.adapter_name,
                    priority=detection.priority,
                    confidence=confidence,
                    metadata=dict(detection.metadata),
                    file_path=rel_path,
                    line=first.line,
                    snippet=first.snippet,
                    evidence_kind="regex",
                )
                self._merge_detection(node_map, comp_det)

        # Enrich DATASTORE nodes with PII/PHI classification metadata
        self._enrich_datastores(node_map, _dc_metadata)

        # Deduplicate nodes that share (component_type, file, line) — e.g. a
        # regex adapter and an AST adapter both firing on the same token.
        _dedup_by_location(node_map)
        # Deduplicate nodes where one name is a prefix of another from the same
        # file — e.g. regex matches "gemini-2.0" while AST extracts the full
        # "gemini-2.0-flash" from an adjacent line of the same call.
        _dedup_by_name_prefix(node_map)

        # Build nodes + edges
        for key in sorted(node_map.keys(), key=lambda v: (v[0].value, v[1])):
            acc = node_map[key]

            # Cross-tier corroboration: each additional source tier adds a
            # small confidence boost (capped at 0.99) because independent
            # evidence from code + IaC or code + docs raises certainty.
            if len(acc.source_tiers) > 1:
                acc.confidence = min(0.99, acc.confidence + 0.03 * (len(acc.source_tiers) - 1))

            node = Node(
                name=acc.display_name,
                component_type=acc.component_type,
                confidence=acc.confidence,
            )
            node.metadata.extras["canonical_name"] = acc.canonical_name
            node.metadata.extras["adapter"] = acc.adapter_name
            node.metadata.extras["evidence_count"] = len(acc.evidence)
            if len(acc.source_tiers) > 1:
                # Expose which tiers corroborated this detection for consumers
                node.metadata.extras["detected_by_tiers"] = sorted(acc.source_tiers)
            node.metadata.extras.update(
                {
                    k: v
                    for k, v in acc.metadata.items()
                    if k
                    not in (
                        "adapter",
                        "evidence_count",
                        "canonical_name",
                        "data_classification",
                        "classified_tables",
                        "classified_fields",
                    )
                }
            )
            # Copy typed metadata fields
            if "framework" in acc.metadata:
                node.metadata.framework = str(acc.metadata["framework"])
            if "provider" in acc.metadata:
                node.metadata.extras["provider"] = acc.metadata["provider"]
            if "model_family" in acc.metadata and acc.metadata["model_family"]:
                node.metadata.extras["model_family"] = acc.metadata["model_family"]
            if "version" in acc.metadata and acc.metadata["version"]:
                node.metadata.extras["version"] = acc.metadata["version"]
            if "model_card_url" in acc.metadata and acc.metadata["model_card_url"]:
                node.metadata.extras["model_card_url"] = acc.metadata["model_card_url"]
            if "api_endpoint" in acc.metadata and acc.metadata["api_endpoint"]:
                node.metadata.extras["api_endpoint"] = acc.metadata["api_endpoint"]
            # Data classification metadata (DATASTORE nodes)
            if acc.component_type == ComponentType.DATASTORE:
                if acc.metadata.get("data_classification"):
                    node.metadata.data_classification = acc.metadata["data_classification"]
                if acc.metadata.get("classified_tables"):
                    node.metadata.classified_tables = acc.metadata["classified_tables"]
                if acc.metadata.get("classified_fields"):
                    node.metadata.classified_fields = acc.metadata["classified_fields"]
            # Container image metadata
            if acc.component_type == ComponentType.CONTAINER_IMAGE:
                node.metadata.image_name = acc.metadata.get("image_name")
                node.metadata.image_tag = acc.metadata.get("image_tag") or None
                node.metadata.image_digest = acc.metadata.get("image_digest")
                node.metadata.registry = acc.metadata.get("registry")
                node.metadata.base_image = acc.metadata.get("base_image")

            node.evidence = list(acc.evidence)
            doc.nodes.append(node)

        self._resolve_edges(doc, node_map)

        # Scan package manifest dependencies (pyproject.toml, requirements*.txt, package.json, …)
        doc.deps = DependencyScanner().scan(root)
        _log.info("deps scan: %d packages found", len(doc.deps))

        # Build deterministic scan-level summary (always populated)
        files_sample = list(file_contents.items())[:200]
        doc.summary = _make_scan_summary(
            build_scan_summary(
                doc.nodes,
                files_sample,
                source_ref=source_ref,
                branch=branch,
                dc_metadata=_dc_metadata,
            )
        )

        # Phase 3: LLM enrichment (skipped unless enable_llm=True)
        if config.enable_llm:
            try:
                doc = asyncio.run(self._llm_enrich(doc, file_contents, config))
            except Exception as exc:  # noqa: BLE001
                _log.warning("LLM enrichment failed, continuing with deterministic output: %s", exc)

        return doc

    def extract_from_repo(self, url: str, ref: str, config: ExtractionConfig) -> AiBomDocument:
        """Clone a git repository and extract an SBOM from it."""
        with tempfile.TemporaryDirectory(prefix="ai_sbom_") as temp_dir:
            repo_dir = Path(temp_dir) / "repo"
            self._clone_repo(url=url, ref=ref, dest=repo_dir)
            return self.extract_from_path(repo_dir, config, source_ref=url, branch=ref)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_python(content: str) -> Any | None:
        """Run the AST parser; return None on parse failure."""
        try:
            from .ast_parser import parse

            result = parse(content)
            return result
        except Exception:
            return None

    @staticmethod
    def _parse_typescript(content: str, file_path: str = "") -> TSParseResult:
        """Parse TypeScript/JavaScript via tree-sitter (or regex fallback)."""
        return _parse_ts_impl(content, file_path or None)

    @staticmethod
    def _extract_notebook_python(content: str) -> str:
        """Extract Python source from a Jupyter notebook (.ipynb).

        Concatenates all ``code`` cell sources separated by blank lines so
        the result can be passed directly to the Python AST parser.
        """
        import json

        try:
            nb = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return ""
        cells = nb.get("cells", [])
        parts: list[str] = []
        for cell in cells:
            if cell.get("cell_type") != "code":
                continue
            source = cell.get("source", "")
            if isinstance(source, list):
                source = "".join(source)
            source = source.strip()
            if source:
                # Strip IPython magic lines (e.g. %pip install, !command)
                clean_lines = [
                    ln for ln in source.splitlines() if not ln.lstrip().startswith(("%", "!"))
                ]
                cleaned = "\n".join(clean_lines).strip()
                if cleaned:
                    parts.append(cleaned)
        return "\n\n".join(parts)

    def _merge_detection(
        self,
        node_map: dict[tuple[ComponentType, str], _NodeAccumulator],
        det: ComponentDetection,
    ) -> None:
        """Merge a ComponentDetection into the accumulator map.

        Applies source-tier precedence: CODE > IAC > DOCS.  When the incoming
        detection comes from a higher tier than what we have accumulated so far,
        its adapter attribution and metadata take precedence.  Evidence from all
        tiers is always appended so the final node reflects every source.
        """
        # Always canonicalize to ensure regex-adapter and AST-adapter nodes
        # for the same component deduplicate correctly.
        canon = canonicalize_text(det.canonical_name)
        key = (det.component_type, canon)
        acc = node_map.get(key)

        tier = _classify_source_tier(det.file_path, det.adapter_name, det.evidence_kind)
        tier_rank = _TIER_RANK.get(tier, 2)

        evidence = Evidence(
            kind=det.evidence_kind,
            confidence=det.confidence,
            detail=f"{det.adapter_name}: {det.snippet[:120]}",
            location=SourceLocation(path=det.file_path, line=det.line or None),
        )

        if acc is None:
            acc = _NodeAccumulator(
                component_type=det.component_type,
                canonical_name=canon,
                display_name=det.display_name,
                adapter_name=det.adapter_name,
                priority=det.priority,
                confidence=det.confidence,
                metadata=dict(det.metadata),
                relationships=list(det.relationships),
                source_tiers={tier},
                best_tier_rank=tier_rank,
            )
            acc.evidence.append(evidence)
            node_map[key] = acc
        else:
            current_best_rank = acc.best_tier_rank  # snapshot before any mutation
            acc.source_tiers.add(tier)

            # Attribution: better tier wins; within the same tier, lower priority wins
            if tier_rank < current_best_rank or (
                tier_rank == current_best_rank and det.priority < acc.priority
            ):
                acc.adapter_name = det.adapter_name
                acc.priority = det.priority
                acc.display_name = det.display_name

            if tier_rank < current_best_rank:
                acc.best_tier_rank = tier_rank

            acc.confidence = max(acc.confidence, det.confidence)

            # Metadata precedence:
            #   Better tier  → its values override existing ones; old unique keys kept
            #   Same/worse tier → only fill gaps (first-write-wins per key)
            if tier_rank < current_best_rank:
                # Incoming detection is from a higher-authority tier.
                # Start from its metadata, then backfill any keys not present
                # from the accumulated metadata so nothing is lost.
                new_meta = {k: v for k, v in det.metadata.items() if v is not None}
                for k, v in acc.metadata.items():
                    if k not in new_meta and v is not None:
                        new_meta[k] = v
                acc.metadata = new_meta
            else:
                for k, v in det.metadata.items():
                    if v is not None:
                        acc.metadata.setdefault(k, v)

            acc.evidence.append(evidence)
            # Accumulate relationship hints
            acc.relationships.extend(det.relationships)

    def _enrich_datastores(
        self,
        node_map: dict[tuple[ComponentType, str], _NodeAccumulator],
        dc_metadata: list[dict],
    ) -> None:
        """Merge PII/PHI classification data from schema adapters into DATASTORE nodes.

        Classification data (from SQL CREATE TABLE and Python model analysis) is
        attached as metadata on every detected DATASTORE node rather than emitted
        as separate nodes.
        """
        if not dc_metadata:
            return
        datastore_keys = [k for k in node_map if k[0] == ComponentType.DATASTORE]
        if not datastore_keys:
            return

        # Aggregate labels, table names, and per-table field detail
        all_labels: set[str] = set()
        classified_tables: list[str] = []
        classified_fields: dict[str, list[str]] = {}
        for meta in dc_metadata:
            all_labels.update(meta.get("data_classification") or [])
            table = meta.get("table_name") or meta.get("model_name")
            if table:
                classified_tables.append(table)
                cf = meta.get("classified_fields")
                if cf:
                    classified_fields[table] = sorted(cf.keys())

        # Merge into every DATASTORE accumulator (project-wide enrichment)
        for key in datastore_keys:
            acc = node_map[key]
            existing_labels = set(acc.metadata.get("data_classification") or [])
            acc.metadata["data_classification"] = sorted(all_labels | existing_labels)
            existing_tables = set(acc.metadata.get("classified_tables") or [])
            acc.metadata["classified_tables"] = sorted(set(classified_tables) | existing_tables)
            existing_cf = dict(acc.metadata.get("classified_fields") or {})
            existing_cf.update(classified_fields)
            acc.metadata["classified_fields"] = existing_cf

    def _resolve_edges(
        self,
        doc: AiBomDocument,
        node_map: dict[tuple[ComponentType, str], _NodeAccumulator],
    ) -> None:
        """Turn RelationshipHints into Edge objects using built node UUIDs.

        Falls back to simple type-based edge inference for any agents that
        don't already have explicit relationships.
        """
        # Build canonical_name → node.id lookup
        canonical_to_id: dict[str, Any] = {}
        for node in doc.nodes:
            canon = node.metadata.extras.get("canonical_name", "")
            if canon:
                canonical_to_id[canon] = node.id

        rel_type_map = {
            "USES": RelationshipType.USES,
            "CALLS": RelationshipType.CALLS,
            "ACCESSES": RelationshipType.ACCESSES,
            "PROTECTS": RelationshipType.PROTECTS,
            "DEPLOYS": RelationshipType.DEPLOYS,
        }

        # Process explicit relationship hints
        seen_edges: set[tuple[Any, Any, str]] = set()
        for acc in node_map.values():
            for hint in acc.relationships:
                src_id = canonical_to_id.get(hint.source_canonical)
                tgt_id = canonical_to_id.get(hint.target_canonical)
                if src_id is None or tgt_id is None:
                    continue
                rel = rel_type_map.get(hint.relationship_type, RelationshipType.USES)
                edge_key = (src_id, tgt_id, hint.relationship_type)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                doc.edges.append(Edge(source=src_id, target=tgt_id, relationship_type=rel))

        # Fallback: connect agents to tools/models they have no explicit link to
        by_type: dict[ComponentType, list[Node]] = {}
        for node in doc.nodes:
            by_type.setdefault(node.component_type, []).append(node)

        agent_ids_with_edges: set[Any] = {e.source for e in doc.edges}

        for agent in by_type.get(ComponentType.AGENT, []):
            if agent.id in agent_ids_with_edges:
                continue  # Already has explicit edges

            for tool in sorted(by_type.get(ComponentType.TOOL, []), key=lambda n: n.name)[:5]:
                key = (agent.id, tool.id, "CALLS")
                if key not in seen_edges:
                    seen_edges.add(key)
                    doc.edges.append(
                        Edge(
                            source=agent.id,
                            target=tool.id,
                            relationship_type=RelationshipType.CALLS,
                        )
                    )
            for model in sorted(by_type.get(ComponentType.MODEL, []), key=lambda n: n.name)[:3]:
                key = (agent.id, model.id, "USES")
                if key not in seen_edges:
                    seen_edges.add(key)
                    doc.edges.append(
                        Edge(
                            source=agent.id,
                            target=model.id,
                            relationship_type=RelationshipType.USES,
                        )
                    )

    async def _llm_enrich(
        self,
        doc: AiBomDocument,
        file_contents: dict[str, str],
        config: ExtractionConfig,
    ) -> AiBomDocument:
        """Phase 3: LLM-based enrichment of detection results.

        Steps:
        1. Verify uncertain nodes (confidence 0.60–0.85) via LLM
        2. Re-aggregate confidence scores with LLM input baked in
        3. Enrich the scan-level use-case summary
        """
        from .llm_client import LLMClient
        from .core.application_summary import maybe_refine_use_case_summary_with_llm
        from .core.confidence import aggregate_node_confidence
        from .core.verification import apply_verification_results, verify_uncertain_nodes

        client = LLMClient(
            model=config.llm_model,
            api_key=config.llm_api_key,
            api_base=config.llm_api_base,
            budget_tokens=config.llm_budget_tokens,
            google_api_key=config.google_api_key,
            vertex_location=config.vertex_location,
        )
        evidence_map = {n.id: n.evidence for n in doc.nodes}

        # Step 1: Verify uncertain detections
        results, v_stats = await verify_uncertain_nodes(
            doc.nodes, evidence_map, client.complete_text, file_contents=file_contents
        )
        doc.nodes = apply_verification_results(doc.nodes, results)
        _log.info("llm verification: %s", v_stats.to_dict())

        # Step 2: Re-aggregate confidence with LLM scores
        doc.nodes, a_stats = aggregate_node_confidence(doc.nodes)
        _log.info("llm confidence aggregation: %s", a_stats.to_dict())

        # Step 3: Refine use-case summary with LLM
        if doc.summary:
            files_sample = list(file_contents.items())[:200]
            llm_ctx = {
                "use_case_summary": doc.summary.use_case,
                "modality_support": doc.summary.modality_support,
                "frameworks": doc.summary.frameworks,
            }
            doc.summary.use_case = await maybe_refine_use_case_summary_with_llm(
                llm_ctx, doc.nodes, files_sample, llm_client=client
            )

        _log.info("llm enrichment complete: tokens_used=%d", client.tokens_used)
        return doc

    @staticmethod
    def _clone_repo(url: str, ref: str, dest: Path) -> None:
        if shutil.which("git") is None:
            raise RuntimeError("git executable not found on PATH")
        cmd = ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)]
        _log.debug("running: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, check=True, capture_output=True)
            _log.debug(
                "git clone succeeded (stderr: %s)",
                result.stderr.decode(errors="replace").strip()[:200] or "(none)",
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode(errors="replace").strip() if exc.stderr else ""
            raise RuntimeError(
                f"git clone failed for {url!r} @ {ref!r}" + (f": {stderr}" if stderr else "")
            ) from exc

    @staticmethod
    def _iter_files(root: Path, config: ExtractionConfig) -> Iterator[Path]:
        count = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            # Always include Dockerfile* files (extensionless or .dockerfile suffix)
            is_dockerfile = (
                suffix in _DOCKERFILE_EXTENSIONS or path.name.lower() in _DOCKERFILE_NAMES
            )
            if suffix not in config.include_extensions and not is_dockerfile:
                continue
            # Skip common irrelevant directories
            parts = set(path.parts)
            if parts & {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".claude"}:
                continue
            # Skip .github/** except .github/workflows/**
            if ".github" in parts and "workflows" not in parts:
                continue
            # Skip meta/tooling instruction files
            if path.name in {"CLAUDE.md", "AGENTS.md"}:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > config.max_file_size_bytes:
                continue
            yield path
            count += 1
            if count >= config.max_files:
                break


def _make_scan_summary(d: dict[str, Any]) -> ScanSummary:
    """Convert the dict from ``build_scan_summary`` into a typed ``ScanSummary``."""
    return ScanSummary(
        use_case=d.get("use_case_summary") or "",
        frameworks=d.get("frameworks") or [],
        modalities=d.get("modalities") or [],
        modality_support=d.get("modality_support") or {},
        api_endpoints=d.get("api_endpoints") or [],
        deployment_platforms=d.get("deployment_platforms") or [],
        regions=d.get("regions") or [],
        environments=d.get("environments") or [],
        deployment_urls=d.get("deployment_urls") or [],
        iac_accounts=d.get("subscription_account_project") or [],
        node_counts=d.get("node_type_counts") or {},
        data_classification=d.get("data_classification") or [],
        classified_tables=d.get("classified_tables") or [],
    )


def _dedup_by_name_prefix(
    node_map: dict[tuple[ComponentType, str], _NodeAccumulator],
) -> None:
    """Remove accumulator entries whose name is a strict prefix of another
    entry of the same component type that shares at least one source file.

    Handles cases where a regex adapter extracts a truncated model name
    (e.g. ``gemini-2.0``) while an AST adapter extracts the full string
    (``gemini-2.0-flash``) from an adjacent line of the same call.
    The shorter entry is dropped and its evidence absorbed by the longer one.
    """
    keys = list(node_map.keys())
    keys_to_remove: set[tuple[ComponentType, str]] = set()

    for i, key_a in enumerate(keys):
        if key_a in keys_to_remove:
            continue
        acc_a = node_map[key_a]
        files_a = {ev.location.path for ev in acc_a.evidence if ev.location}

        for key_b in keys[i + 1 :]:
            if key_b in keys_to_remove:
                continue
            if key_a[0] != key_b[0]:  # must be same component_type
                continue
            acc_b = node_map[key_b]
            files_b = {ev.location.path for ev in acc_b.evidence if ev.location}

            if not files_a & files_b:  # must share at least one file
                continue

            name_a = acc_a.display_name.lower()
            name_b = acc_b.display_name.lower()
            if name_b.startswith(name_a) and name_b != name_a:
                # a is the shorter prefix — drop it, keep b
                node_map[key_b].evidence.extend(node_map[key_a].evidence)
                keys_to_remove.add(key_a)
                _log.debug("dedup_by_name_prefix: dropped %s → kept %s", key_a, key_b)
                break
            elif name_a.startswith(name_b) and name_a != name_b:
                # b is the shorter prefix — drop it, keep a
                node_map[key_a].evidence.extend(node_map[key_b].evidence)
                keys_to_remove.add(key_b)
                _log.debug("dedup_by_name_prefix: dropped %s → kept %s", key_b, key_a)

    for k in keys_to_remove:
        del node_map[k]


def _dedup_by_location(
    node_map: dict[tuple[ComponentType, str], _NodeAccumulator],
) -> None:
    """Remove accumulator entries that share (component_type, file, line) with a
    higher-priority entry, merging their evidence into the winner.

    Applies when two adapters fire on the exact same source token — e.g. an AST
    adapter producing ``gemini-2.0-flash`` and a regex adapter producing
    ``gemini-2.0`` from the same line.  The lower-priority-number (higher
    precedence) adapter wins; ties broken by confidence descending.
    """
    # loc → [key, ...] for all keys that have at least one evidence item at that location
    loc_to_keys: dict[tuple[ComponentType, str, int | None], list[tuple[ComponentType, str]]] = {}
    for key, acc in node_map.items():
        for ev in acc.evidence:
            if ev.location:
                loc = (key[0], ev.location.path, ev.location.line)
                if key not in loc_to_keys.get(loc, []):
                    loc_to_keys.setdefault(loc, []).append(key)

    keys_to_remove: set[tuple[ComponentType, str]] = set()
    for loc, keys in loc_to_keys.items():
        if len(keys) <= 1:
            continue
        # Sort: lower priority number = higher precedence; break ties by confidence desc
        keys_sorted = sorted(
            keys,
            key=lambda k: (node_map[k].priority, -node_map[k].confidence),
        )
        winner = keys_sorted[0]
        for loser in keys_sorted[1:]:
            if loser in keys_to_remove:
                continue
            # Absorb evidence so the winner node reflects all source locations
            node_map[winner].evidence.extend(node_map[loser].evidence)
            keys_to_remove.add(loser)
            _log.debug(
                "dedup_by_location: dropped %s (priority=%d conf=%.2f) → kept %s",
                loser,
                node_map[loser].priority,
                node_map[loser].confidence,
                winner,
            )

    for k in keys_to_remove:
        del node_map[k]


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
