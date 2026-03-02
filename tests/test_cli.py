from __future__ import annotations

import argparse

import pytest

from ai_sbom.cli import _add_scan_args, _add_scan_repo_args


def _scan_path_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    _add_scan_args(parser)
    return parser


def _scan_repo_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    _add_scan_repo_args(parser)
    return parser


def test_scan_path_unified_parses_without_cdx_bom() -> None:
    args = _scan_path_parser().parse_args(
        ["./repo", "--format", "unified", "--output", "unified-bom.json"]
    )
    assert args.format == "unified"
    assert args.output == "unified-bom.json"


def test_scan_path_rejects_cdx_bom_flag() -> None:
    with pytest.raises(SystemExit):
        _scan_path_parser().parse_args(
            [
                "./repo",
                "--format",
                "unified",
                "--output",
                "unified-bom.json",
                "--cdx-bom",
                "standard-bom.json",
            ]
        )


def test_scan_repo_rejects_cdx_bom_flag() -> None:
    with pytest.raises(SystemExit):
        _scan_repo_parser().parse_args(
            [
                "https://github.com/example/project.git",
                "--format",
                "unified",
                "--output",
                "unified-bom.json",
                "--cdx-bom",
                "standard-bom.json",
            ]
        )


def test_scan_path_rejects_deterministic_only_flag() -> None:
    with pytest.raises(SystemExit):
        _scan_path_parser().parse_args(
            [
                "./repo",
                "--output",
                "sbom.json",
                "--deterministic-only",
            ]
        )


def test_scan_repo_rejects_deterministic_only_flag() -> None:
    with pytest.raises(SystemExit):
        _scan_repo_parser().parse_args(
            [
                "https://github.com/example/project.git",
                "--output",
                "sbom.json",
                "--deterministic-only",
            ]
        )
