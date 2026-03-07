"""Tests for the xelo CLI argument parser."""

from __future__ import annotations

import pytest



def _parse(argv: list[str]) -> object:
    """Helper: parse args using main's parser logic by monkey-patching sys.argv."""
    import argparse

    # Build the same parser that main() builds, then parse
    from xelo.cli import _add_llm_args

    parser = argparse.ArgumentParser(prog="xelo")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--debug", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan")
    scan_p.add_argument("target", metavar="<path|url>")
    scan_p.add_argument("--ref", default="main")
    scan_p.add_argument("--format", choices=["json", "cyclonedx", "unified"], default="json")
    scan_p.add_argument("--output", default="-")
    _add_llm_args(scan_p)

    schema_p = subparsers.add_parser("schema")
    schema_p.add_argument("--output", default="-")

    validate_p = subparsers.add_parser("validate")
    validate_p.add_argument("input")

    return parser.parse_args(argv)


def test_scan_unified_parses() -> None:
    args = _parse(["scan", "./repo", "--format", "unified", "--output", "unified-bom.json"])
    assert args.format == "unified"
    assert args.output == "unified-bom.json"


def test_scan_defaults_to_stdout() -> None:
    args = _parse(["scan", "./repo"])
    assert args.output == "-"


def test_scan_rejects_unknown_format() -> None:
    with pytest.raises(SystemExit):
        _parse(["scan", "./repo", "--format", "unknown"])


def test_scan_rejects_cdx_bom_flag() -> None:
    with pytest.raises(SystemExit):
        _parse(["scan", "./repo", "--format", "unified", "--cdx-bom", "standard-bom.json"])


def test_scan_rejects_enable_llm_flag() -> None:
    """Old --enable-llm flag is gone; --llm is the new flag."""
    with pytest.raises(SystemExit):
        _parse(["scan", "./repo", "--enable-llm"])


def test_scan_accepts_llm_flag() -> None:
    args = _parse(["scan", "./repo", "--llm"])
    assert args.llm is True


def test_scan_rejects_deterministic_only_flag() -> None:
    with pytest.raises(SystemExit):
        _parse(["scan", "./repo", "--deterministic-only"])


def test_schema_defaults_to_stdout() -> None:
    args = _parse(["schema"])
    assert args.output == "-"


def test_schema_accepts_output_file() -> None:
    args = _parse(["schema", "--output", "schema.json"])
    assert args.output == "schema.json"


def test_validate_requires_input() -> None:
    args = _parse(["validate", "sbom.json"])
    assert args.input == "sbom.json"
