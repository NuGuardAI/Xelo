"""
AIBOM Schemas Package

Exposes the committed AiBomDocument JSON schema as a Python dict and Path.
The schema file is the canonical serialised form of ``AiBomDocument.model_json_schema()``.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA_PATH: Path = Path(__file__).parent / "aibom.schema.json"

SCHEMA: dict = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

__all__ = ["SCHEMA", "SCHEMA_PATH"]
