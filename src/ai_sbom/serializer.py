"""SBOM serializers: native JSON and CycloneDX 1.6.

``SbomSerializer`` converts an ``AiBomDocument`` (and optional dependency list)
into either the Vela-native JSON format or a standards-compliant CycloneDX 1.6
document.

CycloneDX output structure
--------------------------
``metadata``
    Tool info and the scanned target component.
``components``
    Two groups merged into a single list:

    1. **AI components** (AGENT, MODEL, TOOL, PROMPT, DATASTORE, …) — extracted by
       Vela's framework adapters.  Mapped to CycloneDX ``type`` values:

       - AGENT / FRAMEWORK  → ``"application"``
       - MODEL              → ``"machine-learning-model"``
       - PROMPT             → ``"data"``
       - DATASTORE          → ``"data"``
       - everything else    → ``"library"``

    2. **Package dependencies** (optional ``PackageDep`` list from
       ``DependencyScanner``) — mapped to ``type: "library"`` with proper
       ``purl`` fields following the ``pkg:pypi/`` scheme.

``dependencies``
    Edges from the ``AiBomDocument`` rendered as CycloneDX dependency refs.
"""
from __future__ import annotations

import json
from typing import Any

from .deps import PackageDep
from .models import AiBomDocument
from .types import ComponentType


# CycloneDX component type mapping for AI node types
_AI_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT:        "application",
    ComponentType.FRAMEWORK:    "application",
    ComponentType.MODEL:        "machine-learning-model",
    ComponentType.PROMPT:       "data",
    ComponentType.DATASTORE:    "data",
    ComponentType.TOOL:         "library",
    ComponentType.AUTH:         "library",
    ComponentType.PRIVILEGE:    "library",
    ComponentType.API_ENDPOINT: "library",
    ComponentType.DEPLOYMENT:   "library",
}


class SbomSerializer:
    @staticmethod
    def to_json(doc: AiBomDocument) -> str:
        """Serialise to Vela-native JSON (Pydantic schema)."""
        return doc.model_dump_json(indent=2)

    @staticmethod
    def to_cyclonedx(
        doc: AiBomDocument,
        spec_version: str = "1.6",
        deps: list[PackageDep] | None = None,
    ) -> dict[str, Any]:
        """Build a CycloneDX 1.6 BOM dict.

        Parameters
        ----------
        doc:
            The extracted AI SBOM document.
        spec_version:
            CycloneDX spec version string (default ``"1.6"``).
        deps:
            Optional list of ``PackageDep`` objects from ``DependencyScanner``.
            When provided they are appended as ``library`` components with
            proper ``purl`` values.
        """
        # ── AI component section ──────────────────────────────────────
        ai_components: list[dict[str, Any]] = []
        for node in doc.nodes:
            cdx_type = _AI_TYPE_MAP.get(node.component_type, "library")
            extras = node.metadata.extras

            props: list[dict[str, str]] = [
                {"name": "vela:component_type", "value": node.component_type.value},
                {"name": "vela:confidence",     "value": f"{node.confidence:.2f}"},
            ]
            if extras.get("adapter"):
                props.append({"name": "vela:adapter", "value": str(extras["adapter"])})
            if extras.get("provider"):
                props.append({"name": "vela:provider", "value": str(extras["provider"])})
            if extras.get("model_family"):
                props.append({"name": "vela:model_family", "value": str(extras["model_family"])})
            dc = extras.get("data_classification")
            if dc and isinstance(dc, list):
                props.append({"name": "vela:data_classification", "value": ",".join(dc)})
            cf = extras.get("classified_fields")
            if cf and isinstance(cf, dict):
                # Compact representation: "field:LABEL,LABEL;field2:LABEL"
                cf_str = ";".join(f"{k}:{','.join(v)}" for k, v in sorted(cf.items()))
                props.append({"name": "vela:classified_fields", "value": cf_str})

            component: dict[str, Any] = {
                "bom-ref": str(node.id),
                "type":    cdx_type,
                "name":    node.name,
            }
            if extras.get("version"):
                component["version"] = str(extras["version"])
            if cdx_type == "machine-learning-model" and extras.get("model_card_url"):
                component["externalReferences"] = [
                    {
                        "type": "documentation",
                        "url":  str(extras["model_card_url"]),
                        "comment": "Model card / provider documentation",
                    }
                ]
            if extras.get("api_endpoint"):
                component.setdefault("externalReferences", []).append(  # type: ignore[union-attr]
                    {
                        "type":    "website",
                        "url":     str(extras["api_endpoint"]),
                        "comment": "Provider API endpoint",
                    }
                )
            component["properties"] = props
            ai_components.append(component)

        # ── Dependency component section ──────────────────────────────
        # Use explicit deps when provided; fall back to doc.deps from the scan.
        effective_deps: list[PackageDep] = deps if deps is not None else doc.deps
        dep_components: list[dict[str, Any]] = []
        for dep in effective_deps:
            dc: dict[str, Any] = {
                "bom-ref": dep.purl,
                "type":    "library",
                "name":    dep.name,
                "purl":    dep.purl,
                "properties": [
                    {"name": "vela:dep_group",   "value": dep.group},
                    {"name": "vela:source_file", "value": dep.source_file},
                ],
            }
            if dep.version:
                dc["version"] = dep.version
            if dep.version_spec and dep.version_spec != f"=={dep.version}":
                dc["properties"].append(
                    {"name": "vela:version_spec", "value": dep.version_spec}
                )
            dep_components.append(dc)

        # ── Edge → dependency refs ────────────────────────────────────
        dependencies: list[dict[str, Any]] = [
            {
                "ref":       str(edge.source),
                "dependsOn": [str(edge.target)],
            }
            for edge in doc.edges
        ]

        return {
            "bomFormat":   "CycloneDX",
            "specVersion": spec_version,
            "version":     1,
            "serialNumber": f"urn:uuid:{doc.schema_version}-{doc.generated_at.strftime('%Y%m%dT%H%M%SZ')}",
            "metadata": {
                "timestamp": doc.generated_at.isoformat(),
                "tools": [
                    {
                        "vendor":  "Vela",
                        "name":    doc.generator,
                        "version": "0.2.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": doc.target,
                },
            },
            "components":    ai_components + dep_components,
            "dependencies":  dependencies,
        }

    @staticmethod
    def dump_cyclonedx_json(
        doc: AiBomDocument,
        spec_version: str = "1.6",
        deps: list[PackageDep] | None = None,
    ) -> str:
        return json.dumps(
            SbomSerializer.to_cyclonedx(doc, spec_version=spec_version, deps=deps),
            indent=2,
        )
