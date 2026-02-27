"""Tests for schema generation, anti-drift, and serialization round-trips."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_sbom.cli import _handle_schema
from ai_sbom.config import ExtractionConfig
from ai_sbom.extractor import SbomExtractor
from ai_sbom.models import AiBomDocument
from ai_sbom.serializer import SbomSerializer
from conftest import APPS, PY_ONLY

_SCHEMA_FILE = Path(__file__).parent.parent / "src" / "ai_sbom" / "schemas" / "aibom.schema.json"


class _Args:
    output = ""


# ---------------------------------------------------------------------------
# Schema generation via CLI
# ---------------------------------------------------------------------------


def test_schema_command_writes_schema(tmp_path: Path) -> None:
    args = _Args()
    args.output = str(tmp_path / "schema.json")
    _handle_schema(args)
    payload = json.loads(Path(args.output).read_text(encoding="utf-8"))
    assert payload["title"] == "AiBomDocument"


def test_schema_has_required_top_level_fields(tmp_path: Path) -> None:
    args = _Args()
    args.output = str(tmp_path / "schema.json")
    _handle_schema(args)
    schema = json.loads(Path(args.output).read_text(encoding="utf-8"))
    assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    assert "$id" in schema
    assert "target" in schema["required"]
    defs = schema.get("$defs", {})
    for expected in ("Node", "Edge", "Evidence", "PackageDep", "ScanSummary"):
        assert expected in defs, f"Missing $def: {expected}"


# ---------------------------------------------------------------------------
# Anti-drift: committed schema must match AiBomDocument.model_json_schema()
# ---------------------------------------------------------------------------


def test_committed_schema_matches_models() -> None:
    """aibom.schema.json must stay in sync with AiBomDocument.model_json_schema().

    If this test fails, run from the oss/Xelo directory::

        python -c "
        from ai_sbom.models import AiBomDocument; import json
        open('src/ai_sbom/schemas/aibom.schema.json', 'w').write(
            json.dumps(AiBomDocument.model_json_schema(), indent=2) + '\\n'
        )"
    """
    assert _SCHEMA_FILE.exists(), f"Schema file not found: {_SCHEMA_FILE}"
    committed = json.loads(_SCHEMA_FILE.read_text(encoding="utf-8"))
    live = AiBomDocument.model_json_schema()
    assert committed == live, (
        "aibom.schema.json is out of sync with AiBomDocument Pydantic models. "
        'Regenerate it with: python -c "from ai_sbom.models import AiBomDocument; '
        "import json; open('src/ai_sbom/schemas/aibom.schema.json', 'w')"
        ".write(json.dumps(AiBomDocument.model_json_schema(), indent=2) + '\\n')\""
    )


# ---------------------------------------------------------------------------
# Serialization round-trips
# ---------------------------------------------------------------------------


def test_cyclonedx_empty_doc_has_required_fields() -> None:
    """Minimal document (no nodes) must still produce a valid CycloneDX envelope."""
    payload = SbomSerializer.to_cyclonedx(AiBomDocument(target="sample"))
    assert payload["bomFormat"] == "CycloneDX"
    assert "metadata" in payload
    assert "components" in payload


def test_extracted_doc_validates_against_schema() -> None:
    """A document from SbomExtractor must round-trip through model_validate."""
    doc = SbomExtractor().extract_from_path(APPS / "customer_service_bot", PY_ONLY)
    data = json.loads(SbomSerializer.to_json(doc))
    reparsed = AiBomDocument.model_validate(data)
    assert len(reparsed.nodes) == len(doc.nodes)
    assert len(reparsed.deps) == len(doc.deps)
    assert reparsed.summary is not None
    assert reparsed.summary.use_case


def test_schema_required_field_enforced() -> None:
    """model_validate must reject a document missing the required 'target' field."""
    with pytest.raises(Exception):  # pydantic.ValidationError
        AiBomDocument.model_validate({"nodes": [], "edges": []})
