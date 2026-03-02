"""Xelo CLI — AI SBOM generator.

Commands
--------
xelo scan path <PATH>
    Extract AI components from a local directory.
    --format json          Xelo-native JSON (default)
    --format cyclonedx     AI components only as CycloneDX 1.6
    --format unified       Standard deps BOM + AI-BOM merged (CycloneDX 1.6)

xelo scan repo <URL>
    Clone a git repository and scan it (requires git on PATH).
    Same --format options as scan path.

xelo validate <FILE>
    Validate a Xelo-native JSON file against the AiBomDocument schema.

xelo schema --output <FILE>
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
import os
import sys
import traceback
from pathlib import Path

from .config import ExtractionConfig
from .extractor import SbomExtractor
from .models import AiBomDocument
from .serializer import SbomSerializer

_log = logging.getLogger("xelo")


def _setup_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
    logging.root.setLevel(level)
    logging.root.addHandler(handler)


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Load KEY=VALUE pairs from .env into process environment.

    Existing environment variables are not overridden.
    """
    if not path.exists() or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def _build_extraction_config(args: argparse.Namespace) -> ExtractionConfig:
    config = ExtractionConfig()
    # For scan commands, --enable-llm is the single CLI switch:
    # absent => deterministic only, present => enable enrichment.
    if hasattr(args, "enable_llm"):
        config.enable_llm = bool(args.enable_llm)
    if args.llm_model is not None:
        config.llm_model = args.llm_model
    if args.llm_budget_tokens is not None:
        config.llm_budget_tokens = args.llm_budget_tokens
    if args.llm_api_key is not None:
        config.llm_api_key = args.llm_api_key
    if getattr(args, "llm_api_base", None) is not None:
        config.llm_api_base = args.llm_api_base
    return config


def _die(msg: str, args: argparse.Namespace | None = None) -> None:
    """Print an error and exit 1.  Show traceback only with --debug."""
    debug = getattr(args, "debug", False)
    if debug:
        traceback.print_exc(file=sys.stderr)
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    _load_dotenv()
    parser = argparse.ArgumentParser(
        prog="xelo",
        description="Deterministic AI SBOM generator",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable INFO-level logging to stderr"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable DEBUG-level logging and full tracebacks"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan a path or repository")
    scan_sub = scan_parser.add_subparsers(dest="scan_command", required=True)

    _add_scan_args(scan_sub.add_parser("path", help="Scan a local directory"))
    _add_scan_repo_args(scan_sub.add_parser("repo", help="Clone and scan a git repo"))

    # ── validate ─────────────────────────────────────────────────────────
    validate_parser = subparsers.add_parser("validate", help="Validate a Xelo JSON file")
    validate_parser.add_argument("input", help="Path to Xelo-native JSON file")

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
            "json=Xelo-native, "
            "cyclonedx=AI components as CycloneDX, "
            "unified=standard deps + AI merged CycloneDX (default: json)"
        ),
    )
    p.add_argument("--output", required=True, metavar="<file>")
    p.add_argument(
        "--enable-llm",
        dest="enable_llm",
        action="store_true",
        help="Enable LLM enrichment for this run.",
    )
    p.add_argument(
        "--llm-model",
        metavar="<model>",
        help="LLM model string for enrichment (overrides AISBOM_LLM_MODEL).",
    )
    p.add_argument(
        "--llm-budget-tokens",
        type=int,
        metavar="<n>",
        help="Token budget for LLM enrichment (overrides AISBOM_LLM_BUDGET_TOKENS).",
    )
    p.add_argument(
        "--llm-api-key",
        metavar="<key>",
        help="Direct API key for LLM calls (overrides AISBOM_LLM_API_KEY).",
    )
    p.add_argument(
        "--llm-api-base",
        metavar="<url>",
        help="Base URL for LLM calls (overrides AISBOM_LLM_API_BASE, e.g. Azure AI Foundry endpoint).",
    )


def _add_scan_repo_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("url", metavar="<url>")
    p.add_argument("--ref", default="main")
    p.add_argument("--format", choices=["json", "cyclonedx", "unified"], default="json")
    p.add_argument("--output", required=True, metavar="<file>")
    p.add_argument(
        "--enable-llm",
        dest="enable_llm",
        action="store_true",
        help="Enable LLM enrichment for this run.",
    )
    p.add_argument(
        "--llm-model",
        metavar="<model>",
        help="LLM model string for enrichment (overrides AISBOM_LLM_MODEL).",
    )
    p.add_argument(
        "--llm-budget-tokens",
        type=int,
        metavar="<n>",
        help="Token budget for LLM enrichment (overrides AISBOM_LLM_BUDGET_TOKENS).",
    )
    p.add_argument(
        "--llm-api-key",
        metavar="<key>",
        help="Direct API key for LLM calls (overrides AISBOM_LLM_API_KEY).",
    )
    p.add_argument(
        "--llm-api-base",
        metavar="<url>",
        help="Base URL for LLM calls (overrides AISBOM_LLM_API_BASE, e.g. Azure AI Foundry endpoint).",
    )


def _handle_scan(args: argparse.Namespace) -> None:
    extractor = SbomExtractor()
    config = _build_extraction_config(args)
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
            _log.info("writing Xelo-native JSON → %s", out)
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
    """Generate the standard CycloneDX BOM then merge with AI-BOM."""
    from .cdx_tools import CycloneDxGenerator
    from .merger import AiBomMerger

    _log.info("generating standard CycloneDX BOM for %s", root)
    gen = CycloneDxGenerator()
    std_bom, method = gen.generate(root)
    _log.info("standard BOM generated via %s", method)

    _log.info(
        "merging standard BOM (%d components) with AI-BOM (%d nodes)",
        len(std_bom.get("components", [])),
        len(ai_doc.nodes),
    )
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
