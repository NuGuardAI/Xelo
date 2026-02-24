"""Velo CLI — AI SBOM generator.

Commands
--------
velo scan path <PATH>
    Extract AI components from a local directory.
    --format json          Vela-native JSON (default)
    --format cyclonedx     AI components only as CycloneDX 1.6
    --format unified       Standard deps BOM + AI-BOM merged (CycloneDX 1.6)
    --cdx-bom <FILE>       Supply a pre-generated CycloneDX BOM to merge into
                           instead of running the built-in generator.

velo scan repo <URL>
    Clone a git repository and scan it (requires git on PATH).
    Same --format options as scan path.

velo validate <FILE>
    Validate a Vela-native JSON file against the AiBomDocument schema.

velo schema --output <FILE>
    Write the AiBomDocument JSON schema to a file.

Logging
-------
  --verbose   INFO-level logs to stderr (scan progress, file counts, fallbacks)
  --debug     DEBUG-level logs + full tracebacks on errors
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from pathlib import Path

from .config import ExtractionConfig
from .extractor import SbomExtractor
from .models import AiBomDocument
from .serializer import SbomSerializer

_log = logging.getLogger("vela")


def _setup_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
    logging.root.setLevel(level)
    logging.root.addHandler(handler)


def _die(msg: str, args: argparse.Namespace | None = None) -> None:
    """Print an error and exit 1.  Show traceback only with --debug."""
    debug = getattr(args, "debug", False)
    if debug:
        traceback.print_exc(file=sys.stderr)
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vela",
        description="Deterministic AI SBOM generator",
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable INFO-level logging to stderr")
    parser.add_argument("--debug", action="store_true",
                        help="Enable DEBUG-level logging and full tracebacks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan a path or repository")
    scan_sub = scan_parser.add_subparsers(dest="scan_command", required=True)

    _add_scan_args(scan_sub.add_parser("path", help="Scan a local directory"))
    _add_scan_repo_args(scan_sub.add_parser("repo", help="Clone and scan a git repo"))

    # ── validate ─────────────────────────────────────────────────────────
    validate_parser = subparsers.add_parser("validate", help="Validate a Velo JSON file")
    validate_parser.add_argument("input", help="Path to Vela-native JSON file")

    # ── schema ────────────────────────────────────────────────────────────
    schema_parser = subparsers.add_parser("schema", help="Export the AiBomDocument JSON schema")
    schema_parser.add_argument("--output", required=True, metavar="<file>")

    args = parser.parse_args()
    _setup_logging(args.verbose, args.debug)

    if args.command == "scan":
        _handle_scan(args)
    elif args.command == "validate":
        _handle_validate(args)
    elif args.command == "schema":
        _handle_schema(args)


def _add_scan_args(p: argparse.ArgumentParser) -> None:  # noqa: D401
    p.add_argument("path", metavar="<path>", help="Directory to scan")
    p.add_argument(
        "--format",
        choices=["json", "cyclonedx", "unified"],
        default="json",
        help=(
            "Output format: "
            "json=Vela-native, "
            "cyclonedx=AI components as CycloneDX, "
            "unified=standard deps + AI merged CycloneDX (default: json)"
        ),
    )
    p.add_argument("--output", required=True, metavar="<file>")
    p.add_argument(
        "--cdx-bom",
        metavar="<file>",
        dest="cdx_bom",
        help="Path to an existing CycloneDX BOM JSON to merge with (unified format only). "
             "If omitted, Velo generates one automatically.",
    )


def _add_scan_repo_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("url", metavar="<url>")
    p.add_argument("--ref", default="main")
    p.add_argument("--format", choices=["json", "cyclonedx", "unified"], default="json")
    p.add_argument("--output", required=True, metavar="<file>")
    p.add_argument("--cdx-bom", metavar="<file>", dest="cdx_bom")


def _handle_scan(args: argparse.Namespace) -> None:
    extractor = SbomExtractor()
    config = ExtractionConfig()
    root: Path

    try:
        if args.scan_command == "path":
            root = Path(args.path).resolve()
            if not root.exists():
                _die(f"path not found: {root}", args)
            if not root.is_dir():
                _die(f"not a directory: {root}", args)
            _log.info("scanning %s", root)
            doc = extractor.extract_from_path(root, config=config)
        else:
            _log.info("cloning %s @ %s", args.url, args.ref)
            doc = extractor.extract_from_repo(args.url, ref=args.ref, config=config)
            root = Path(".")
    except RuntimeError as exc:
        _die(str(exc), args)
        return  # unreachable — satisfies type checker

    _log.info("extraction complete: %d nodes, %d edges", len(doc.nodes), len(doc.edges))

    out = Path(args.output)
    _write_output(args, doc, root, out)


def _write_output(
    args: argparse.Namespace,
    doc: AiBomDocument,
    root: Path,
    out: Path,
) -> None:
    """Serialise *doc* to *out* in the requested format."""
    fmt: str = args.format

    try:
        if fmt == "json":
            _log.info("writing Vela-native JSON → %s", out)
            out.write_text(SbomSerializer.to_json(doc), encoding="utf-8")

        elif fmt == "cyclonedx":
            _log.info("writing CycloneDX 1.6 JSON → %s", out)
            out.write_text(SbomSerializer.dump_cyclonedx_json(doc), encoding="utf-8")

        else:
            # unified: standard BOM + AI-BOM merge
            _handle_unified(args, root, doc, out)

    except PermissionError as exc:
        _die(f"cannot write output file: {exc}", args)
    except OSError as exc:
        _die(f"I/O error writing {out}: {exc}", args)

    _log.info("done — %s written", out)
    print(f"{len(doc.nodes)} nodes, {len(doc.edges)} edges → {out}")


def _handle_unified(
    args: argparse.Namespace,
    root: Path,
    ai_doc: AiBomDocument,
    out: Path,
) -> None:
    """Generate or load the standard CycloneDX BOM then merge with AI-BOM."""
    from .cdx_tools import CycloneDxGenerator
    from .merger import AiBomMerger

    if getattr(args, "cdx_bom", None):
        cdx_path = Path(args.cdx_bom)
        _log.info("loading supplied CycloneDX BOM from %s", cdx_path)
        try:
            raw = cdx_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            _die(f"--cdx-bom file not found: {cdx_path}", args)
            return
        except OSError as exc:
            _die(f"cannot read --cdx-bom file: {exc}", args)
            return
        try:
            std_bom = json.loads(raw)
        except json.JSONDecodeError as exc:
            _die(f"--cdx-bom is not valid JSON: {exc}", args)
            return
        method = f"supplied:{args.cdx_bom}"
    else:
        _log.info("generating standard CycloneDX BOM for %s", root)
        gen = CycloneDxGenerator()
        std_bom, method = gen.generate(root)
        _log.info("standard BOM generated via %s", method)

    _log.info("merging standard BOM (%d components) with AI-BOM (%d nodes)",
              len(std_bom.get("components", [])), len(ai_doc.nodes))
    merger = AiBomMerger()
    unified = merger.merge(std_bom, ai_doc, generator_method=method)

    try:
        out.write_text(json.dumps(unified, indent=2), encoding="utf-8")
    except OSError as exc:
        _die(f"cannot write unified BOM to {out}: {exc}", args)


def _handle_validate(args: argparse.Namespace) -> None:
    in_path = Path(args.input)
    _log.info("validating %s", in_path)
    try:
        raw = in_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _die(f"file not found: {in_path}", args)
        return
    except OSError as exc:
        _die(f"cannot read file: {exc}", args)
        return
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _die(f"not valid JSON: {exc}", args)
        return
    try:
        AiBomDocument.model_validate(data)
    except Exception as exc:
        _die(f"validation failed: {exc}", args)
        return
    print("OK — document is valid")


def _handle_schema(args: argparse.Namespace) -> None:
    out = Path(args.output)
    _log.info("writing JSON schema → %s", out)
    schema = AiBomDocument.model_json_schema()
    try:
        out.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    except OSError as exc:
        _die(f"cannot write schema to {out}: {exc}", args)
    print(f"schema written → {out}")


if __name__ == "__main__":
    main()
