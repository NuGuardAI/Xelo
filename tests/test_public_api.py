from __future__ import annotations

from xelo import AiBomDocument, ExtractionConfig, SbomExtractor, SbomSerializer


def test_xelo_public_api_exports() -> None:
    assert AiBomDocument is not None
    assert ExtractionConfig is not None
    assert SbomExtractor is not None
    assert SbomSerializer is not None
