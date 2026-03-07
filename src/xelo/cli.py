"""Xelo CLI — AI SBOM generator.

Commands
--------
xelo scan <PATH|URL>
    Extract AI components from a local directory or a remote git repo.
    Target is treated as a URL when it contains ``://``.

    --format json          Xelo-native JSON (default)
    --format cyclonedx     AI components only as CycloneDX 1.6
    --format unified       Standard deps BOM + AI-BOM merged (CycloneDX 1.6)
    --output <file>        Write to file (default: stdout)
    --llm                  Enable LLM enrichment for this run
    --ref <branch>         Branch/ref to clone when target is a URL

xelo validate <FILE>
    Validate a Xelo-native JSON document against the schema.

xelo schema [--output <file>]
    Emit the Xelo JSON schema.

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

from .config import AiSbomConfig
from .extractor import AiSbomExtractor
from .models import AiSbomDocument
from .serializer import AiSbomSerializer

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


def _build_extraction_config(args: argparse.Namespace) -> AiSbomConfig:
    config = AiSbomConfig()
    if getattr(args, "llm", False):
        config.enable_llm = True
    if getattr(args, "llm_model", None) is not None:
        config.llm_model = args.llm_model
    if getattr(args, "llm_budget_tokens", None) is not None:
        config.llm_budget_tokens = args.llm_budget_tokens
    if getattr(args, "llm_api_key", None) is not None:
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


def _add_llm_args(p: argparse.ArgumentParser) -> None:
    """Attach LLM flags to a sub-parser."""
    p.add_argument("--llm", action="store_true", help="Enable LLM enrichment for this run.")
    p.add_argument(
        "--llm-model", metavar="<model>", help="LLM model string (overrides XELO_LLM_MODEL)."
    )
    p.add_argument(
        "--llm-budget-tokens",
        type=int,
        metavar="<n>",
        help="Token budget (overrides XELO_LLM_BUDGET_TOKENS).",
    )
    p.add_argument(
        "--llm-api-key", metavar="<key>", help="LLM API key (overrides XELO_LLM_API_KEY)."
    )
    p.add_argument(
        "--llm-api-base", metavar="<url>", help="LLM base URL (overrides XELO_LLM_API_BASE)."
    )


def main() -> None:
    _load_dotenv()
    parser = argparse.ArgumentParser(prog="xelo", description="Deterministic AI SBOM generator")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable INFO-level logging to stderr"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable DEBUG-level logging and full tracebacks"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser("scan", help="Scan a local directory or remote git repo")
    scan_p.add_argument(
        "target", metavar="<path|url>", help="Local path or git URL (detected by '://')"
    )
    scan_p.add_argument(
        "--ref",
        default="main",
        metavar="<branch>",
        help="Branch/ref when target is a URL (default: main)",
    )
    scan_p.add_argument(
        "--format",
        choices=["json", "cyclonedx", "unified"],
        default="json",
        help="Output format: json (default), cyclonedx, unified",
    )
    scan_p.add_argument(
        "--output", default="-", metavar="<file>", help="Output file (default: stdout)"
    )
    _add_llm_args(scan_p)

    # ── validate ──────────────────────────────────────────────────────────
    validate_p = subparsers.add_parser("validate", help="Validate a Xelo-native JSON document")
    validate_p.add_argument("input", metavar="<file>")

    # ── schema ────────────────────────────────────────────────────────────
    schema_p = subparsers.add_parser("schema", help="Emit the Xelo JSON schema")
    schema_p.add_argument(
        "--output", default="-", metavar="<file>", help="File to write schema to (default: stdout)"
    )

    args = parser.parse_args()
    _setup_logging(args.verbose, args.debug)

    command_map = {
        "scan": _handle_scan,
        "validate": _handle_validate,
        "schema": _handle_schema,
    }
    handler = command_map.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(args)


# ── scan ──────────────────────────────────────────────────────────────────────


def _handle_scan(args: argparse.Namespace) -> None:
    extractor = AiSbomExtractor()
    config = _build_extraction_config(args)
    target: str = args.target

    try:
        if "://" in target:
            _log.info("cloning %s @ %s", target, args.ref)
            doc = extractor.extract_from_repo(target, ref=args.ref, config=config)
            local_root = Path(".")
        else:
            local_root = Path(target).resolve()
            if not local_root.exists():
                _die(f"path not found: {local_root}", args)
            if not local_root.is_dir():
                _die(f"not a directory: {local_root}", args)
            _log.info("scanning %s", local_root)
            doc = extractor.extract_from_path(local_root, config=config)
    except RuntimeError as exc:
        _die(str(exc), args)
        return

    _log.info("extraction complete: %d nodes, %d edges", len(doc.nodes), len(doc.edges))
    _write_output(args, doc, local_root, args.output)


def _write_output(
    args: argparse.Namespace,
    doc: AiSbomDocument,
    root: Path,
    output: str,
) -> None:
    fmt: str = args.format
    try:
        if fmt == "json":
            content = AiSbomSerializer.to_json(doc)
        elif fmt == "cyclonedx":
            content = AiSbomSerializer.dump_cyclonedx_json(doc)
        else:
            content = _build_unified(args, root, doc)
    except (PermissionError, OSError) as exc:
        _die(f"I/O error: {exc}", args)
        return

    _emit(content, output, args)
    if output != "-":
        _log.info("done — %s written", output)
        print(f"{len(doc.nodes)} nodes, {len(doc.edges)} edges → {output}")
    else:
        _log.info("done — %d nodes, %d edges", len(doc.nodes), len(doc.edges))


def _build_unified(args: argparse.Namespace, root: Path, ai_doc: AiSbomDocument) -> str:
    from .cdx_tools import CycloneDxGenerator
    from .merger import AiBomMerger

    gen = CycloneDxGenerator()
    std_bom, method = gen.generate(root)
    merger = AiBomMerger()
    unified = merger.merge(std_bom, ai_doc, generator_method=method)
    return json.dumps(unified, indent=2)


def _emit(content: str, output: str, args: argparse.Namespace) -> None:
    if output == "-":
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
    else:
        try:
            Path(output).write_text(content, encoding="utf-8")
        except OSError as exc:
            _die(f"cannot write {output}: {exc}", args)


# ── validate ──────────────────────────────────────────────────────────────────


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
        AiSbomDocument.model_validate(data)
    except Exception as exc:
        _die(f"validation failed: {exc}", args)
        return
    print("OK — document is valid")


# ── schema ────────────────────────────────────────────────────────────────────


def _handle_schema(args: argparse.Namespace) -> None:
    schema = AiSbomDocument.model_json_schema()
    content = json.dumps(schema, indent=2)
    output: str = args.output
    _emit(content, output, args)
    if output != "-":
        print(f"schema written → {output}")


if __name__ == "__main__":
    main()
