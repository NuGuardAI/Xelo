"""xelo-toolbox CLI.

Commands
--------
toolbox deps analyze    --sbom <file>
toolbox vuln scan       --sbom <file> [--provider xelo-rules|osv|grype|all]
toolbox license check   --sbom <file> --policy <file>
toolbox cyclonedx export --sbom <file>
toolbox xray submit     --sbom <file> --url <url> --project <key> --token <tok> …

Output
------
Every command writes its result JSON to a file.  The default location is
``./output/<command>-<action>-<sbom-stem>.json`` (directory is created
automatically).  Override with ``--output <path>``.

All commands also print their result JSON to stdout so they compose
naturally in shell pipelines.

Logging
-------
  --verbose / -v   INFO-level logs to stderr
  --debug          DEBUG-level logs + full tracebacks on errors
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

from xelo_toolbox.core import Toolbox

_log = logging.getLogger("toolbox")

_OUTPUT_DIR = Path("output")


# ---------------------------------------------------------------------------
# Logging + error helpers  (same pattern as Vela)
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
    logging.root.setLevel(level)
    logging.root.addHandler(handler)


def _die(msg: str, args: argparse.Namespace | None = None) -> None:
    """Print an error message to stderr and exit with code 1.

    With ``--debug`` the full traceback is shown.
    """
    if getattr(args, "debug", False):
        traceback.print_exc(file=sys.stderr)
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _default_output(command: str, action: str, sbom_path: str, ext: str = "json") -> Path:
    """Return ``./output/<command>-<action>-<sbom-stem>.<ext>``."""
    stem = Path(sbom_path).stem
    return _OUTPUT_DIR / f"{command}-{action}-{stem}.{ext}"


def _ensure_dir(path: Path, args: argparse.Namespace) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _die(f"cannot create output directory '{path.parent}': {exc}", args)


def _write_output(result: object, out: Path, args: argparse.Namespace) -> None:
    """Serialise *result* to *out* and print JSON to stdout."""
    payload = result.model_dump() if hasattr(result, "model_dump") else result
    text = json.dumps(payload, indent=2)

    _ensure_dir(out, args)
    try:
        out.write_text(text, encoding="utf-8")
    except PermissionError as exc:
        _die(f"cannot write to '{out}': {exc}", args)
    except OSError as exc:
        _die(f"I/O error writing '{out}': {exc}", args)

    _log.info("result written → %s", out)
    print(text)
    print(f"→ {out}", file=sys.stderr)


def _load_json(path: str, args: argparse.Namespace) -> dict[str, Any]:
    p = Path(path)
    _log.debug("loading %s", p)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        _die(f"file not found: {p}", args)
        raise  # unreachable — satisfies type checker
    except OSError as exc:
        _die(f"cannot read '{p}': {exc}", args)
        raise
    try:
        loaded: dict[str, object] = json.loads(raw)
        return loaded
    except json.JSONDecodeError as exc:
        _die(f"'{p}' is not valid JSON: {exc}", args)
        raise


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    cleaned = cleaned.strip("-._")
    return cleaned or "scan"


def _default_scan_output(command: str, action: str, args: argparse.Namespace) -> Path:
    if getattr(args, "scan_path", ""):
        stem = _slugify(Path(args.scan_path).name)
        kind = "path"
    elif getattr(args, "scan_repo", ""):
        stem = _slugify(args.scan_repo.rsplit("/", 1)[-1].replace(".git", ""))
        kind = "repo"
    else:
        stem = "scan"
        kind = "input"
    return _OUTPUT_DIR / f"{command}-{action}-{kind}-{stem}.sbom.json"


def _resolve_sbom_path(command: str, action: str, args: argparse.Namespace) -> Path:
    sbom = getattr(args, "sbom", "")
    if sbom:
        return Path(sbom)

    scan_path = getattr(args, "scan_path", "")
    scan_repo = getattr(args, "scan_repo", "")
    if not scan_path and not scan_repo:
        _die("one of --sbom, --scan-path, or --scan-repo is required", args)
        raise RuntimeError("unreachable")

    out = Path(args.scan_output) if getattr(args, "scan_output", "") else _default_scan_output(command, action, args)
    _ensure_dir(out, args)

    scan_cmd = [sys.executable, "-m", "ai_sbom.cli", "scan"]
    if scan_path:
        scan_cmd.extend(["path", scan_path])
    else:
        scan_cmd.extend(["repo", scan_repo])
        if getattr(args, "scan_ref", ""):
            scan_cmd.extend(["--ref", args.scan_ref])

    scan_cmd.extend(["--format", "json", "--output", str(out)])

    if getattr(args, "scan_cdx_bom", ""):
        scan_cmd.extend(["--cdx-bom", args.scan_cdx_bom])
    if getattr(args, "enable_llm", False):
        scan_cmd.append("--enable-llm")
    if getattr(args, "llm_model", ""):
        scan_cmd.extend(["--llm-model", args.llm_model])
    if getattr(args, "llm_budget_tokens", None) is not None:
        scan_cmd.extend(["--llm-budget-tokens", str(args.llm_budget_tokens)])
    if getattr(args, "llm_api_key", ""):
        scan_cmd.extend(["--llm-api-key", args.llm_api_key])

    _log.info("running xelo discovery: %s", " ".join(scan_cmd))
    try:
        proc = subprocess.run(scan_cmd, check=False, capture_output=True, text=True)
    except OSError as exc:
        _die(f"cannot run xelo discovery command: {exc}", args)
        raise RuntimeError("unreachable")

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown discovery error"
        _die(f"xelo discovery failed: {detail}", args)
        raise RuntimeError("unreachable")

    print(f"discovery SBOM → {out}", file=sys.stderr)
    return out


def _add_sbom_or_scan_args(parser: argparse.ArgumentParser, command: str, action: str) -> None:
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--sbom", help="Path to an existing SBOM JSON file")
    src.add_argument("--scan-path", "--path", dest="scan_path",
                     help="Local folder to scan with xelo discovery")
    src.add_argument("--scan-repo", "--repo", dest="scan_repo",
                     help="GitHub repository URL to scan with xelo discovery")
    parser.add_argument("--scan-ref", "--ref", dest="scan_ref", default="",
                        help="Git ref/branch/tag to scan (repo mode only)")
    parser.add_argument("--scan-output", default="",
                        help=(
                            "Where to write discovery SBOM JSON "
                            f"(default: output/{command}-{action}-<source>.sbom.json)"
                        ))
    parser.add_argument("--scan-cdx-bom", default="",
                        help="Path to an existing CycloneDX BOM to merge in discovery")
    llm_mode = parser.add_mutually_exclusive_group(required=False)
    llm_mode.add_argument("--enable-llm", action="store_true",
                          help="Enable LLM enrichment during discovery")
    parser.add_argument("--llm-model", default="", help="LLM model for discovery enrichment")
    parser.add_argument("--llm-budget-tokens", type=int, default=None,
                        help="Token budget for discovery enrichment")
    parser.add_argument("--llm-api-key", default="", help="Direct API key for discovery enrichment")


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

_MAIN_DESCRIPTION = """\
xelo-toolbox — AI SBOM integration and analysis toolkit.

Consumes a Vela-generated SBOM (JSON) and runs one of the built-in plugins:
  deps         Analyse AI components and package dependencies
  vuln         Scan for data-classification and structural risk signals
  license      Enforce a license deny-list across nodes and deps
  cyclonedx    Export the SBOM to CycloneDX 1.6 format
  xray         Submit the SBOM to JFrog Xray
  aws-sechub   Push findings to AWS Security Hub
  policy       Assess SBOM compliance against a NuGuard Standard policy file

Output files are written to ./output/ by default (created automatically).
"""

_MAIN_EPILOG = """\
Examples:
  # Scan a local folder with xelo discovery, then run dependency analysis
  xelo-toolbox deps analyze --path /workspace/my-app

  # Scan a GitHub repo with xelo discovery, then run vulnerability scanning
  xelo-toolbox vuln scan --repo https://github.com/org/repo.git --ref main --provider all

  # Dependency breakdown
  xelo-toolbox deps analyze --sbom sbom.json

  # Vulnerability scan (structural rules only, no network)
  xelo-toolbox vuln scan --sbom sbom.json

  # Vulnerability scan + OSV CVE lookup
  xelo-toolbox vuln scan --sbom sbom.json --provider osv

  # License check against a policy file
  xelo-toolbox license check --sbom sbom.json --policy policy.json

  # CycloneDX export
  xelo-toolbox cyclonedx export --sbom sbom.json

  # CycloneDX export with OSV vulnerability annotations (BOM+VEX)
  xelo-toolbox cyclonedx export --sbom sbom.json --include-vulnerabilities

  # Submit to JFrog Xray
  xelo-toolbox xray submit \\
      --sbom sbom.json \\
      --url https://xray.example.com \\
      --project MY-PROJECT \\
      --token $XRAY_TOKEN \\
      --tenant-id tenant-1 \\
      --application-id app-1

  # Push structural VLA findings to AWS Security Hub
  xelo-toolbox aws-sechub push \\
      --sbom sbom.json \\
      --region us-east-1 \\
      --account-id 123456789012

  # Verbose logging
  xelo-toolbox --verbose vuln scan --sbom sbom.json --provider osv
"""

_DEPS_EPILOG = """\
Examples:
  xelo-toolbox deps analyze --sbom sbom.json
  xelo-toolbox deps analyze --sbom sbom.json --output results/deps.json

Output includes:
  total_ai_nodes      — number of AI component nodes (MODEL, TOOL, DATASTORE, …)
  ai_component_counts — breakdown by component_type
  total_package_deps  — number of package dependencies in the SBOM deps list
  package_dep_groups  — breakdown by dep group (ai, general, …)
  node_counts         — node_counts dict from the SBOM summary (if present)
"""

_VULN_EPILOG = """\
Examples:
  # Structural rules only (no network, default)
  xelo-toolbox vuln scan --sbom sbom.json

  # Structural rules + OSV CVE lookup for package deps
  xelo-toolbox vuln scan --sbom sbom.json --provider osv

  # Both passes
  xelo-toolbox vuln scan --sbom sbom.json --provider all

  # Grype only (must have grype installed: https://github.com/anchore/grype)
  xelo-toolbox vuln scan --sbom sbom.json --provider grype

Providers:
  all         Structural rules + OSV CVE lookup + Grype (default)
  osv         OSV CVE/GHSA lookup for deps only (requires network)
  xelo-rules  Structural graph checks only (offline)

Status semantics:
  failed   Confirmed CVE in a dependency (OSV) at HIGH or CRITICAL severity
  warning  Structural/heuristic advisories (VLA-xxx) or low-severity CVEs
  ok       No findings

Structural signals detected:
  VLA-001  No guardrails protecting AI models            CRITICAL
  VLA-002  PHI/PII sent to external LLM providers        CRITICAL
  VLA-003  PHI API endpoints with minimal auth           HIGH
  VLA-004  Privileged components without guardrails      HIGH
  VLA-005  Voice modality with PHI                       HIGH
  VLA-006  Models with no output validation              MEDIUM
  VLA-007  Prompt injection risk                         MEDIUM
  VLA-008  Multi-provider LLM fan-out                    MEDIUM
  VLA-009  API surface exceeds auth coverage             LOW
"""

_LICENSE_EPILOG = """\
Policy file format (JSON):
  { "deny": ["GPL-3.0", "AGPL-3.0"] }

Examples:
  xelo-toolbox license check --sbom sbom.json --policy policy.json
  xelo-toolbox license check --sbom sbom.json --policy policy.json --output results/license.json

Output includes:
  violations    — list of {source, name, license} for each violation
  nodes_checked — number of SBOM nodes inspected
  deps_checked  — number of package deps inspected
"""

_CYCLONEDX_EPILOG = """\
Examples:
  # BOM only
  xelo-toolbox cyclonedx export --sbom sbom.json

  # Custom output path
  xelo-toolbox cyclonedx export --sbom sbom.json --output bom.json

  # BOM + VEX (OSV vulnerability annotations)
  xelo-toolbox cyclonedx export --sbom sbom.json --include-vulnerabilities

The output file is a CycloneDX 1.6 BOM in JSON format.
With --include-vulnerabilities, known CVEs from OSV are attached as a
CycloneDX ``vulnerabilities`` array, producing a combined BOM+VEX document
consumable by Grype, Trivy, and other CycloneDX-aware scanners.
DATASTORE nodes with PII/PHI metadata emit xelo:data_classification
and xelo:classified_fields properties.
"""

_ATLAS_EPILOG = """\
Examples:
  # Annotate SBOM with ATLAS techniques (offline, no network needed)
  xelo-toolbox atlas annotate --sbom sbom.json

  # Annotate and write output to a specific path
  xelo-toolbox atlas annotate --sbom sbom.json --output reports/atlas.json

  # Annotate via a Vela scan URL
  xelo-toolbox atlas annotate \\
      --repo https://github.com/org/repo

All analysis is static (offline). No LLM or network call is made.
Findings are annotated with MITRE ATLAS v2 technique IDs, tactic names,
confidence levels, and suggested mitigations.
"""

_GHAS_EPILOG = """\
Examples:
  # Upload structural findings (offline scan, real API upload)
  xelo-toolbox ghas upload \\
      --sbom sbom.json \\
      --token $GITHUB_TOKEN \\
      --github-repo org/my-repo \\
      --git-ref refs/heads/main \\
      --commit-sha $(git rev-parse HEAD)

  # Include OSV CVE advisories in the upload
  xelo-toolbox ghas upload \\
      --sbom sbom.json \\
      --token $GITHUB_TOKEN \\
      --github-repo org/my-repo \\
      --git-ref refs/pull/42/merge \\
      --commit-sha $(git rev-parse HEAD) \\
      --provider osv

  # GitHub Enterprise Server
  xelo-toolbox ghas upload \\
      --sbom sbom.json \\
      --token $GITHUB_TOKEN \\
      --github-repo org/my-repo \\
      --git-ref refs/heads/main \\
      --commit-sha $(git rev-parse HEAD) \\
      --github-api-url https://github.example.com/api/v3

Required token scopes:
  Classic token : security_events (+ repo for private repositories)
  Fine-grained  : Security events — Read and write

Findings appear in Security → Code scanning after upload.
"""

_SECHUB_EPILOG = """\
Examples:
  # Push VLA structural findings (offline, no network)
  xelo-toolbox aws-sechub push \\
      --sbom sbom.json \\
      --region us-east-1 \\
      --account-id 123456789012

  # Push findings including OSV CVE advisories
  xelo-toolbox aws-sechub push \\
      --sbom sbom.json \\
      --region us-east-1 \\
      --account-id 123456789012 \\
      --provider osv

  # Use a named AWS credential profile
  xelo-toolbox aws-sechub push \\
      --sbom sbom.json \\
      --region eu-west-1 \\
      --account-id 123456789012 \\
      --profile my-aws-profile

Credentials are resolved via the standard boto3 chain:
  1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
  2. Named profile (--profile) from ~/.aws/credentials
  3. EC2 / ECS / Lambda instance role

Requires boto3:
  pip install "xelo-toolbox[aws]"
"""

_XRAY_EPILOG = """\
Examples:
  xelo-toolbox xray submit \\
      --sbom sbom.json \\
      --url https://xray.example.com \\
      --project MY-PROJECT \\
      --token $XRAY_TOKEN \\
      --tenant-id tenant-1 \\
      --application-id app-1

Project keys must be alphanumeric with hyphens/underscores only.
"""

_MARKDOWN_EPILOG = """\
Examples:
  xelo-toolbox markdown export --sbom sbom.json
  xelo-toolbox markdown export --sbom sbom.json --output report.md

Output includes:
  Summary table    — node/dep counts, data classification, frameworks, modalities
  AI Components    — name, component_type, and confidence for each SBOM node
  Dependencies     — name, version, group, license for each package dep
  Node Breakdown   — per-type counts from summary.node_counts (if present)
"""

_SARIF_EPILOG = """\
Examples:
  # Structural rules only (offline, default)
  xelo-toolbox sarif export --sbom sbom.json

  # Include OSV CVE advisories
  xelo-toolbox sarif export --sbom sbom.json --provider osv

  # Full scan (structural + OSV + Grype)
  xelo-toolbox sarif export --sbom sbom.json --provider all

  # Custom output path
  xelo-toolbox sarif export --sbom sbom.json --output findings.sarif.json

The output is a SARIF 2.1.0 JSON document consumable by GitHub Code Scanning,
VS Code SARIF Viewer, and other SARIF-aware tools.

Severity → SARIF level mapping:
  CRITICAL / HIGH  → error
  MEDIUM           → warning
  LOW / INFO       → note
"""

_POLICY_EPILOG = """\
Examples:
  # Assess SBOM against the NIST AI RMF policy using GPT-4o
  xelo-toolbox policy assess \\
      --sbom sbom.json \\
      --policy tests/benchmark/policies/nist_ai_rmf_nuguard_standard.json \\
      --assess-model gpt-4o \\
      --assess-key $OPENAI_API_KEY

  # Use a local repo path for keyword scanning + Anthropic model
  xelo-toolbox policy assess \\
      --sbom sbom.json \\
      --policy policies/owasp_ai_top10_nuguard_standard.json \\
      --repo-path /workspace/my-app \\
      --assess-model anthropic/claude-3-5-sonnet-20241022

  # Custom output path
  xelo-toolbox policy assess \\
      --sbom sbom.json \\
      --policy policy.json \\
      --assess-model gpt-4o \\
      --output results/nist-assessment.json

The LLM is called once per control.  Each control result mirrors the
NuGuard Standard GAP/COVERED shape: status, confidence, evidence refs,
and repo-specific remediation.

Status semantics:
  failed   One or more CRITICAL/HIGH controls assessed as GAP (confidence ≥ 0.5)
  warning  One or more non-critical GAP controls
  ok       All controls assessed as COVERED
"""

_FMT = argparse.RawDescriptionHelpFormatter


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xelo-toolbox",
        description=_MAIN_DESCRIPTION,
        epilog=_MAIN_EPILOG,
        formatter_class=_FMT,
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable INFO-level logging to stderr")
    parser.add_argument("--debug", action="store_true",
                        help="Enable DEBUG-level logging and full tracebacks on errors")

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # ── ghas ─────────────────────────────────────────────────────────────────
    ghas = subparsers.add_parser(
        "ghas",
        help="Upload SBOM findings to GitHub Code Scanning (GHAS)",
        description=(
            "Build a SARIF 2.1.0 document from Xelo SBOM findings and upload it "
            "to GitHub Code Scanning via the REST API. "
            "Findings appear in Security → Code scanning and are annotated on PRs."
        ),
        epilog=_GHAS_EPILOG,
        formatter_class=_FMT,
    )
    ghas_sub = ghas.add_subparsers(dest="action", required=True, metavar="<action>")
    ghas_upload = ghas_sub.add_parser(
        "upload",
        help="Upload SARIF to GitHub Code Scanning",
        epilog=_GHAS_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(ghas_upload, "ghas", "upload")
    ghas_upload.add_argument("--token", required=True,
                             help="GitHub token with security_events:write scope")
    ghas_upload.add_argument("--github-repo", required=True, dest="github_repo",
                             metavar="OWNER/REPO",
                             help="Repository slug (e.g. org/my-repo)")
    ghas_upload.add_argument("--git-ref", required=True, dest="git_ref",
                             help="Git ref for the upload (e.g. refs/heads/main)")
    ghas_upload.add_argument("--commit-sha", required=True, dest="commit_sha",
                             help="40-character commit SHA")
    ghas_upload.add_argument("--github-api-url", default="https://api.github.com",
                             dest="github_api_url",
                             help="GitHub API base URL (default: https://api.github.com; "
                                  "override for GitHub Enterprise Server)")
    ghas_upload.add_argument("--provider", default="xelo-rules",
                             choices=["xelo-rules", "osv", "grype", "all"],
                             help=(
                                 "xelo-rules=structural only, offline (default); "
                                 "osv=OSV advisory DB; "
                                 "grype=Grype scanner; "
                                 "all=structural+OSV+Grype"
                             ))
    ghas_upload.add_argument("--timeout", type=float, default=15.0,
                             help="HTTP timeout in seconds (default: 15)")
    ghas_upload.add_argument("--retries", type=int, default=2,
                             help="Number of retry attempts (default: 2)")
    ghas_upload.add_argument("--output", metavar="<file>",
                             help="Write result JSON to this path "
                                  "(default: output/ghas-upload-<stem>.json)")

    # ── atlas ────────────────────────────────────────────────────────────────
    atlas = subparsers.add_parser(
        "atlas",
        help="Annotate SBOM findings with MITRE ATLAS v2 techniques",
        description=(
            "Run a two-pass static analysis against a Xelo SBOM and annotate "
            "each finding with MITRE ATLAS v2 technique IDs, tactic names, "
            "confidence levels, and suggested mitigations. "
            "All analysis is offline (no network required)."
        ),
        epilog=_ATLAS_EPILOG,
        formatter_class=_FMT,
    )
    atlas_sub = atlas.add_subparsers(dest="action", required=True, metavar="<action>")
    atlas_annotate = atlas_sub.add_parser(
        "annotate",
        help="Annotate SBOM with ATLAS techniques",
        epilog=_ATLAS_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(atlas_annotate, "atlas", "annotate")
    atlas_annotate.add_argument(
        "--output", metavar="<file>",
        help="Write result JSON to this path (default: output/atlas-annotate-<stem>.json)",
    )

    # ── aws-sechub ───────────────────────────────────────────────────────────
    sechub = subparsers.add_parser(
        "aws-sechub",
        help="Push SBOM findings to AWS Security Hub",
        description="Translate Xelo SBOM findings to ASFF and import into AWS Security Hub.",
        epilog=_SECHUB_EPILOG,
        formatter_class=_FMT,
    )
    sechub_sub = sechub.add_subparsers(dest="action", required=True, metavar="<action>")
    sechub_push = sechub_sub.add_parser(
        "push",
        help="Import findings into AWS Security Hub",
        epilog=_SECHUB_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(sechub_push, "aws-sechub", "push")
    sechub_push.add_argument("--region",     required=True,
                             help="AWS region (e.g. us-east-1)")
    sechub_push.add_argument("--account-id", required=True, dest="account_id",
                             help="12-digit AWS account ID")
    sechub_push.add_argument("--profile",    default=None,
                             help="AWS named credential profile (default: boto3 chain)")
    sechub_push.add_argument("--product-arn-suffix", default="xelo-toolbox",
                             dest="product_arn_suffix",
                             help="Product ARN suffix (default: xelo-toolbox)")
    sechub_push.add_argument("--provider",   default="xelo-rules",
                             choices=["xelo-rules", "osv", "grype", "all"],
                             help=(
                                 "xelo-rules=structural only, offline (default); "
                                 "osv=OSV advisory DB; "
                                 "grype=Grype scanner; "
                                 "all=structural+OSV+Grype"
                             ))
    sechub_push.add_argument("--timeout",       type=float, default=15.0,
                             help="Network timeout in seconds for OSV (default: 15)")
    sechub_push.add_argument("--grype-timeout", type=float, default=60.0,
                             help="Grype subprocess timeout in seconds (default: 60)")
    sechub_push.add_argument("--output", metavar="<file>",
                             help="Write result JSON to this path "
                                  "(default: output/aws-sechub-push-<stem>.json)")

    # ── xray ────────────────────────────────────────────────────────────────
    xray = subparsers.add_parser(
        "xray",
        help="Submit SBOM to JFrog Xray",
        description="Submit a Xelo SBOM to JFrog Xray for security scanning.",
        epilog=_XRAY_EPILOG,
        formatter_class=_FMT,
    )
    xray_sub = xray.add_subparsers(dest="action", required=True, metavar="<action>")
    xray_submit = xray_sub.add_parser(
        "submit",
        help="POST SBOM to JFrog Xray",
        epilog=_XRAY_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(xray_submit, "xray", "submit")
    xray_submit.add_argument("--url",            required=True, help="Xray base URL")
    xray_submit.add_argument("--project",        required=True, help="Xray project key")
    xray_submit.add_argument("--token",          required=True, help="Bearer token")
    xray_submit.add_argument("--tenant-id",      required=True, help="Tenant identifier")
    xray_submit.add_argument("--application-id", required=True, help="Application identifier")
    xray_submit.add_argument("--timeout",        type=float, default=10.0, help="HTTP timeout in seconds (default: 10)")
    xray_submit.add_argument("--retries",        type=int,   default=2,    help="Number of retry attempts (default: 2)")
    xray_submit.add_argument("--output", metavar="<file>",
                              help="Write result JSON to this path (default: output/xray-submit-<stem>.json)")

    # ── vuln ────────────────────────────────────────────────────────────────
    vuln = subparsers.add_parser(
        "vuln",
        help="Scan SBOM for risk signals",
        description="Detect data-classification and structural risk signals in a Xelo SBOM.",
        epilog=_VULN_EPILOG,
        formatter_class=_FMT,
    )
    vuln_sub = vuln.add_subparsers(dest="action", required=True, metavar="<action>")
    vuln_scan = vuln_sub.add_parser(
        "scan",
        help="Run vulnerability / risk scan",
        epilog=_VULN_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(vuln_scan, "vuln", "scan")
    vuln_scan.add_argument("--provider", default="all",
                           choices=["xelo-rules", "osv", "grype", "all"],
                           help=(
                               "all=structural+OSV+Grype (default); "
                               "xelo-rules=structural only (offline); "
                               "osv=OSV advisory DB only; "
                               "grype=Grype scanner only (must be installed)"
                           ))
    vuln_scan.add_argument("--timeout",  type=float, default=15.0,
                           help="Network timeout in seconds for OSV requests (default: 15)")
    vuln_scan.add_argument("--grype-timeout", type=float, default=60.0,
                           help="Subprocess timeout in seconds for Grype (default: 60)")
    vuln_scan.add_argument("--output", metavar="<file>",
                           help="Write result JSON to this path (default: output/vuln-scan-<stem>.json)")

    # ── deps ────────────────────────────────────────────────────────────────
    deps = subparsers.add_parser(
        "deps",
        help="Analyse AI components and package dependencies",
        description="Break down AI component types and package dependency groups in a Xelo SBOM.",
        epilog=_DEPS_EPILOG,
        formatter_class=_FMT,
    )
    deps_sub = deps.add_subparsers(dest="action", required=True, metavar="<action>")
    deps_analyze = deps_sub.add_parser(
        "analyze",
        help="Run dependency analysis",
        epilog=_DEPS_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(deps_analyze, "deps", "analyze")
    deps_analyze.add_argument("--output", metavar="<file>",
                              help="Write result JSON to this path (default: output/deps-analyze-<stem>.json)")

    # ── license ─────────────────────────────────────────────────────────────
    license_cmd = subparsers.add_parser(
        "license",
        help="Check license policy across nodes and deps",
        description="Enforce a license deny-list across SBOM nodes and package dependencies.",
        epilog=_LICENSE_EPILOG,
        formatter_class=_FMT,
    )
    license_sub = license_cmd.add_subparsers(dest="action", required=True, metavar="<action>")
    license_check = license_sub.add_parser(
        "check",
        help="Run license policy check",
        epilog=_LICENSE_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(license_check, "license", "check")
    license_check.add_argument("--policy", required=True,
                               help='Path to policy JSON file — {"deny": ["GPL-3.0", ...]}')
    license_check.add_argument("--output", metavar="<file>",
                               help="Write result JSON to this path (default: output/license-check-<stem>.json)")

    # ── cyclonedx ───────────────────────────────────────────────────────────
    cyclonedx = subparsers.add_parser(
        "cyclonedx",
        help="Export SBOM to CycloneDX 1.6 format",
        description="Convert a Xelo SBOM to a CycloneDX 1.6 JSON BOM.",
        epilog=_CYCLONEDX_EPILOG,
        formatter_class=_FMT,
    )
    cyclonedx_sub = cyclonedx.add_subparsers(dest="action", required=True, metavar="<action>")
    cyclonedx_export = cyclonedx_sub.add_parser(
        "export",
        help="Write CycloneDX BOM to a file",
        epilog=_CYCLONEDX_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(cyclonedx_export, "cyclonedx", "export")
    cyclonedx_export.add_argument("--output", metavar="<file>",
                                  help="Destination path (default: output/cyclonedx-export-<stem>.json)")
    cyclonedx_export.add_argument("--include-vulnerabilities", action="store_true", default=False,
                                  help="Query OSV and attach a CycloneDX vulnerabilities array (BOM+VEX)")
    cyclonedx_export.add_argument("--provider", default="osv",
                                  choices=["osv", "all"],
                                  help="Vulnerability provider for --include-vulnerabilities (default: osv)")
    cyclonedx_export.add_argument("--timeout",  type=float, default=15.0,
                                  help="Network timeout in seconds (default: 15)")

    # ── markdown ─────────────────────────────────────────────────────────────
    markdown = subparsers.add_parser(
        "markdown",
        help="Export SBOM to a Markdown report",
        description="Render a Xelo SBOM as a human-readable Markdown document.",
        epilog=_MARKDOWN_EPILOG,
        formatter_class=_FMT,
    )
    markdown_sub = markdown.add_subparsers(dest="action", required=True, metavar="<action>")
    markdown_export = markdown_sub.add_parser(
        "export",
        help="Write Markdown report to a file",
        epilog=_MARKDOWN_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(markdown_export, "markdown", "export")
    markdown_export.add_argument("--output", metavar="<file>",
                                 help="Destination path (default: output/markdown-export-<stem>.md)")

    # ── sarif ─────────────────────────────────────────────────────────────────
    sarif = subparsers.add_parser(
        "sarif",
        help="Export vulnerability findings to SARIF 2.1.0",
        description="Run the vulnerability scanner and emit a SARIF 2.1.0 document.",
        epilog=_SARIF_EPILOG,
        formatter_class=_FMT,
    )
    sarif_sub = sarif.add_subparsers(dest="action", required=True, metavar="<action>")
    sarif_export = sarif_sub.add_parser(
        "export",
        help="Write SARIF 2.1.0 document to a file",
        epilog=_SARIF_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(sarif_export, "sarif", "export")
    sarif_export.add_argument("--provider", default="xelo-rules",
                              choices=["xelo-rules", "osv", "grype", "all"],
                              help=(
                                  "xelo-rules=structural only, offline (default); "
                                  "osv=OSV advisory DB; "
                                  "grype=Grype scanner; "
                                  "all=structural+OSV+Grype"
                              ))
    sarif_export.add_argument("--timeout",      type=float, default=15.0,
                              help="Network timeout in seconds for OSV (default: 15)")
    sarif_export.add_argument("--grype-timeout", type=float, default=60.0,
                              help="Subprocess timeout in seconds for Grype (default: 60)")
    sarif_export.add_argument("--output", metavar="<file>",
                              help="Destination path (default: output/sarif-export-<stem>.sarif.json)")

    # ── policy ────────────────────────────────────────────────────────────────
    policy_cmd = subparsers.add_parser(
        "policy",
        help="Assess SBOM compliance against a NuGuard Standard policy file",
        description=(
            "Evaluate each policy control against the AIBOM using three phases: "
            "AIBOM inspection, keyword-based repo scan, and LLM synthesis."
        ),
        epilog=_POLICY_EPILOG,
        formatter_class=_FMT,
    )
    policy_sub = policy_cmd.add_subparsers(dest="action", required=True, metavar="<action>")
    policy_assess = policy_sub.add_parser(
        "assess",
        help="Run full policy assessment (AIBOM + repo scan + LLM)",
        epilog=_POLICY_EPILOG,
        formatter_class=_FMT,
    )
    _add_sbom_or_scan_args(policy_assess, "policy", "assess")
    policy_assess.add_argument(
        "--policy", required=True, metavar="<file>",
        help="Path to a *_nuguard_standard.json policy file",
    )
    policy_assess.add_argument(
        "--repo-path", default="", metavar="<path>",
        help=(
            "Repository source for keyword scanning.  Accepts:\n"
            "  • local directory path (default: current working directory)\n"
            "  • GitHub URL: https://github.com/owner/repo[/tree/branch]\n"
            "    (requires --repo-github-token or GITHUB_TOKEN env var for private repos)\n"
            "  • cached_files.json path produced by the benchmark fetcher"
        ),
    )
    policy_assess.add_argument(
        "--assess-model", required=True, metavar="<model>",
        help=(
            "litellm model string for assessment LLM, e.g. 'gpt-4o' or "
            "'anthropic/claude-3-5-sonnet-20241022'"
        ),
    )
    policy_assess.add_argument(
        "--assess-key", default="", metavar="<key>",
        help="API key for the assessment LLM (default: reads OPENAI_API_KEY env)",
    )
    policy_assess.add_argument(
        "--assess-base", default="", metavar="<url>",
        help="Custom API base URL for the assessment LLM (proxies / local models)",
    )
    policy_assess.add_argument(
        "--max-repo-hits", type=int, default=25, metavar="<n>",
        help="Maximum keyword-match lines returned per control (default: 25)",
    )
    policy_assess.add_argument(
        "--repo-github-token", default="", metavar="<token>",
        help=(
            "GitHub personal access token for private-repo access "
            "(default: GITHUB_TOKEN env var).  Only required when --repo-path "
            "is a GitHub URL."
        ),
    )
    policy_assess.add_argument(
        "--output", metavar="<file>",
        help="Write result JSON to this path (default: output/policy-assess-<stem>.json)",
    )

    return parser


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _dispatch(args: argparse.Namespace) -> None:
    toolbox = Toolbox()

    if args.command == "ghas":
        sbom_path = _resolve_sbom_path("ghas", "upload", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("ghas", "upload", str(sbom_path))
        _log.info(
            "uploading SARIF to GitHub Code Scanning (repo=%s, ref=%s, provider=%s)",
            args.github_repo, args.ref, args.provider,
        )
        try:
            result = toolbox.run("ghas_upload", sbom, {
                "token":          args.token,
                "github_repo":    args.github_repo,
                "ref":            args.git_ref,
                "commit_sha":     args.commit_sha,
                "github_api_url": args.github_api_url,
                "provider":       args.provider,
                "timeout":        args.timeout,
                "retries":        args.retries,
            })
        except (ValueError, RuntimeError) as exc:
            _die(f"ghas upload failed: {exc}", args)
            return
        _write_output(result, out, args)
        count = result.details.get("finding_count", 0)
        url   = result.details.get("analysis_url", "")
        print(
            f"{count} finding(s) uploaded [status={result.status}]"
            + (f" → {url}" if url else f" → {out}"),
            file=sys.stderr,
        )
        return

    if args.command == "atlas":
        sbom_path = _resolve_sbom_path("atlas", "annotate", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("atlas", "annotate", str(sbom_path))
        _log.info("running ATLAS annotation")
        result = toolbox.run("atlas_annotate", sbom, {})
        _write_output(result, out, args)
        total = result.details.get("total_findings", 0)
        techniques = result.details.get("techniques_identified") or []
        print(
            f"{total} finding(s), {len(techniques)} unique ATLAS technique(s) "
            f"[status={result.status}] → {out}",
            file=sys.stderr,
        )
        return

    if args.command == "aws-sechub":
        sbom_path = _resolve_sbom_path("aws-sechub", "push", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("aws-sechub", "push", str(sbom_path))
        _log.info(
            "pushing findings to AWS Security Hub (region=%s, account=%s, provider=%s)",
            args.region, args.account_id, args.provider,
        )
        try:
            result = toolbox.run("securityhub_push", sbom, {
                "region":             args.region,
                "aws_account_id":     args.account_id,
                "product_arn_suffix": args.product_arn_suffix,
                "profile":            args.profile,
                "provider":           args.provider,
                "timeout":            args.timeout,
                "grype_timeout":      args.grype_timeout,
            })
        except (ImportError, RuntimeError) as exc:
            _die(str(exc), args)
            return
        _write_output(result, out, args)
        submitted = result.details.get("submitted", 0)
        failed    = result.details.get("failed", 0)
        print(
            f"{submitted} finding(s) submitted"
            + (f", {failed} failed" if failed else "")
            + f" [status={result.status}] → {out}",
            file=sys.stderr,
        )
        return

    if args.command == "xray":
        sbom_path = _resolve_sbom_path("xray", "submit", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("xray", "submit", str(sbom_path))
        _log.info("running xray submit → %s", args.url)
        try:
            result = toolbox.run("xray_submit", sbom, {
                "url":            args.url,
                "project":        args.project,
                "token":          args.token,
                "tenant_id":      args.tenant_id,
                "application_id": args.application_id,
                "timeout":        args.timeout,
                "retries":        args.retries,
            })
        except RuntimeError as exc:
            _die(f"xray submit failed: {exc}", args)
            return
        _write_output(result, out, args)
        return

    if args.command == "vuln":
        sbom_path = _resolve_sbom_path("vuln", "scan", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("vuln", "scan", str(sbom_path))
        _log.info("running vuln scan (provider=%s)", args.provider)
        result = toolbox.run("vuln_scan", sbom, {
            "provider":      args.provider,
            "timeout":       args.timeout,
            "grype_timeout": args.grype_timeout,
        })
        _write_output(result, out, args)
        return

    if args.command == "deps":
        sbom_path = _resolve_sbom_path("deps", "analyze", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("deps", "analyze", str(sbom_path))
        _log.info("running dependency analysis")
        result = toolbox.run("dependency_analyze", sbom, {})
        _write_output(result, out, args)
        return

    if args.command == "license":
        sbom_path = _resolve_sbom_path("license", "check", args)
        sbom   = _load_json(str(sbom_path), args)
        policy = _load_json(args.policy, args)
        out    = Path(args.output) if args.output else _default_output("license", "check", str(sbom_path))
        deny   = policy.get("deny", [])
        _log.info("running license check (deny_list=%s)", deny)
        result = toolbox.run("license_check", sbom, {"deny": deny})
        _write_output(result, out, args)
        return

    if args.command == "markdown":
        sbom_path = _resolve_sbom_path("markdown", "export", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("markdown", "export", str(sbom_path), ext="md")
        _log.info("running markdown export")
        result = toolbox.run("markdown_export", sbom, {})
        _ensure_dir(out, args)
        markdown_text = result.details.get("markdown", "")
        try:
            out.write_text(markdown_text, encoding="utf-8")
        except OSError as exc:
            _die(f"cannot write Markdown report to '{out}': {exc}", args)
        _log.info("Markdown report written → %s", out)
        node_count = len(sbom.get("nodes") or [])
        dep_count  = len(sbom.get("deps") or [])
        print(f"{node_count} node(s), {dep_count} dep(s) → {out}", file=sys.stderr)
        return

    if args.command == "sarif":
        sbom_path = _resolve_sbom_path("sarif", "export", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("sarif", "export", str(sbom_path), ext="sarif.json")
        _log.info("running sarif export (provider=%s)", args.provider)
        result = toolbox.run("sarif_export", sbom, {
            "provider":      args.provider,
            "timeout":       args.timeout,
            "grype_timeout": args.grype_timeout,
        })
        _ensure_dir(out, args)
        try:
            out.write_text(json.dumps(result.details, indent=2), encoding="utf-8")
        except OSError as exc:
            _die(f"cannot write SARIF document to '{out}': {exc}", args)
        _log.info("SARIF document written → %s", out)
        result_count = len((result.details.get("runs") or [{}])[0].get("results") or [])
        print(f"{result_count} result(s) [status={result.status}] → {out}", file=sys.stderr)
        return

    if args.command == "cyclonedx":
        sbom_path = _resolve_sbom_path("cyclonedx", "export", args)
        sbom = _load_json(str(sbom_path), args)
        out  = Path(args.output) if args.output else _default_output("cyclonedx", "export", str(sbom_path))
        _log.info("running cyclonedx export (include_vulnerabilities=%s)", args.include_vulnerabilities)
        result = toolbox.run("cyclonedx_export", sbom, {
            "include_vulnerabilities": args.include_vulnerabilities,
            "provider":  args.provider,
            "timeout":   args.timeout,
        })
        _ensure_dir(out, args)
        try:
            out.write_text(json.dumps(result.details, indent=2), encoding="utf-8")
        except OSError as exc:
            _die(f"cannot write CycloneDX BOM to '{out}': {exc}", args)
        _log.info("CycloneDX BOM written → %s", out)
        vex_count = len(result.details.get("vulnerabilities") or [])
        comp_count = len(result.details.get("components") or [])
        print(f"{comp_count} component(s)"
              + (f", {vex_count} vulnerability record(s)" if vex_count else "")
              + f" → {out}", file=sys.stderr)

    if args.command == "policy":
        sbom_path = _resolve_sbom_path("policy", "assess", args)
        sbom      = _load_json(str(sbom_path), args)
        out       = Path(args.output) if args.output else _default_output("policy", "assess", str(sbom_path))
        repo_path = args.repo_path or ""
        llm_key   = args.assess_key or ""
        _log.info("running policy assessment (model=%s, policy=%s)", args.assess_model, args.policy)
        try:
            result = toolbox.run("policy_assess", sbom, {
                "policy_file":   args.policy,
                "llm_model":     args.assess_model,
                "repo_path":     repo_path,
                "llm_api_key":   llm_key or None,
                "llm_api_base":  args.assess_base or None,
                "max_repo_hits": args.max_repo_hits,
                "github_token":  args.repo_github_token or None,
            })
        except (ValueError, RuntimeError) as exc:
            _die(str(exc), args)
            return
        _write_output(result, out, args)
        summary = result.details.get("summary", {})
        print(
            f"{summary.get('covered', '?')}/{summary.get('total', '?')} controls covered "
            f"[status={result.status}] → {out}",
            file=sys.stderr,
        )
        return


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    _setup_logging(args.verbose, args.debug)
    _log.debug("args: %s", vars(args))

    try:
        _dispatch(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        _die(f"unexpected error: {exc}", args)


if __name__ == "__main__":
    main()
