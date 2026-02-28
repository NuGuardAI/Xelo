"""Shared helpers for all Xelo tests.

Import these directly in test modules::

    from conftest import APPS, FIXTURES, PY_ONLY, extract, nodes, names, adapters
"""

from __future__ import annotations

from pathlib import Path

from ai_sbom.config import ExtractionConfig
from ai_sbom.extractor import SbomExtractor
from ai_sbom.models import AiBomDocument
from ai_sbom.types import ComponentType

# ---------------------------------------------------------------------------
# Canonical fixture roots
# ---------------------------------------------------------------------------

#: Rich scenario fixtures — each subdirectory is one AI application
APPS: Path = Path(__file__).parent / "fixtures" / "apps"

#: Flat fixture root — simpler integration fixtures live here directly
FIXTURES: Path = Path(__file__).parent / "fixtures"

#: Default config: Python-only, deterministic
PY_ONLY: ExtractionConfig = ExtractionConfig(
    include_extensions={".py"},
    deterministic_only=True,
)


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def extract(path: Path, config: ExtractionConfig | None = None) -> AiBomDocument:
    """Run SbomExtractor on *path* using *config* (default: PY_ONLY)."""
    return SbomExtractor().extract_from_path(path, config or PY_ONLY)


def nodes(doc: AiBomDocument, typ: ComponentType) -> list:
    """Return all nodes in *doc* with the given component type."""
    return [n for n in doc.nodes if n.component_type == typ]


def names(doc: AiBomDocument, ctype: ComponentType) -> set[str]:
    """Return lowercase node names filtered by component type."""
    return {n.name.lower() for n in doc.nodes if n.component_type == ctype}


def adapters(doc: AiBomDocument) -> set[str]:
    """Return the set of adapter names present anywhere in *doc*."""
    return {n.metadata.extras.get("adapter", "") for n in doc.nodes}
