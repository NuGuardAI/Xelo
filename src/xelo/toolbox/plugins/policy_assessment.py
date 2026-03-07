"""Policy assessment plugin for Xelo AI SBOMs.

Evaluates each NuGuard Standard policy control against an AIBOM in three
phases:

Phase 1 — AIBOM Inspection (always)
  Matches SBOM nodes by component_type, resolves summary/metadata field
  paths specified in evidence_queries.aibom_node_types and
  evidence_queries.aibom_metadata_fields.

Phase 2 — Repo Scan (skipped when inventory_coverage.level == "full")
  Walks the repository tree with a compiled regex built from
  evidence_queries.keywords.  Returns file, line, and matched content
  snippets, capped at max_repo_hits per control.

  repo_path may be:
    - A local filesystem directory path  (default / most common)
    - A GitHub URL (https://github.com/owner/repo or .../tree/branch)
      The plugin fetches source files via the GitHub REST API into a
      temporary directory, scans them, then deletes the directory.
      Set github_token in config (or GITHUB_TOKEN env var) to raise the
      API rate limit from 60 to 5000 req/h.

Phase 3 — LLM Synthesis (always, LLM model is required)
  Submits consolidated evidence to the configured LLM for a final
  GAP / COVERED assessment with confidence score, evidence refs, and
  repo-specific remediation guidance.  Called once per control.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from xelo_toolbox.models import ToolResult
from xelo_toolbox.plugin_base import ToolPlugin

_log = logging.getLogger("toolbox.plugins.policy_assess")


# ---------------------------------------------------------------------------
# Repo scanner constants
# ---------------------------------------------------------------------------

_SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".ts", ".js", ".ipynb",".yaml", ".yml", ".json", ".md", ".tf",
    ".toml", ".txt", ".env", ".sh",
})

_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "build", "dist", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    ".tox", "eggs", ".eggs",
})

# Path-prefix patterns to ignore regardless of directory depth.
# These are coding-agent / IDE configuration folders, not application source.
_SKIP_PATH_PREFIXES: tuple[str, ...] = (
    ".github/chatmodes/",
    ".github/skills/",
    ".claude/",
)

# GitHub REST API — maximum files fetched per repo
_GITHUB_MAX_FILES = 500


# ---------------------------------------------------------------------------
# GitHub URL helpers  (module-private)
# ---------------------------------------------------------------------------

def _is_cached_files_json(path: str) -> bool:
    """Return True if *path* is a file whose name contains ``cached_files`` and ends in ``.json``."""
    p = Path(path)
    return p.is_file() and p.suffix.lower() == ".json" and "cached_files" in p.name.lower()


def _load_cached_files_to_tmpdir(json_path: str) -> tuple[str, Any]:
    """Load a ``cached_files.json`` (``{"files": [{"path": str, "content": str}]}``) \
into a tmpdir for keyword scanning.

    Returns ``(tmpdir_path, cleanup_fn)``.  The caller must always call
    ``cleanup_fn()`` when finished.
    """
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)

    files: list[dict[str, str]] = data.get("files") or []
    _log.info(
        "[cached-files] loading %d files from %r",
        len(files), json_path,
    )

    tmpdir = tempfile.mkdtemp(prefix="policy_assess_cache_")

    def _cleanup() -> None:
        shutil.rmtree(tmpdir, ignore_errors=True)

    written = 0
    for entry in files:
        rel = entry.get("path", "")
        content = entry.get("content", "")
        if not rel:
            continue
        dest = Path(tmpdir) / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_text(content, encoding="utf-8")
            written += 1
        except OSError:
            pass

    _log.info("[cached-files] wrote %d/%d files into %s", written, len(files), tmpdir)
    return tmpdir, _cleanup


def _is_github_url(path: str) -> bool:
    """Return True if *path* looks like a GitHub repository URL."""
    return path.startswith("https://github.com/") or path.startswith("http://github.com/")


def _parse_github_url(url: str) -> tuple[str, str, str]:
    """Parse a GitHub URL into (owner, repo, branch).

    Accepted forms:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/branch
        https://github.com/owner/repo/tree/branch/subpath  (subpath ignored)

    Returns (owner, repo, branch) — branch defaults to ``"main"``.
    """
    stripped = re.sub(r"^https?://github\.com/", "", url.rstrip("/"))
    parts = stripped.split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse GitHub URL: {url!r}")
    owner = parts[0]
    repo  = parts[1].removesuffix(".git")
    # …/tree/<branch>[/subpath]
    branch = parts[3] if len(parts) >= 4 and parts[2] == "tree" else "main"
    return owner, repo, branch


async def _async_github_fetch(
    owner: str,
    repo:  str,
    branch: str,
    token: str | None,
    max_files: int,
) -> list[tuple[str, str]]:
    """Fetch source files from a GitHub repo via the REST API.

    Returns a list of ``(relative_path, content_str)`` pairs, capped at
    *max_files*.  Binary / large files are skipped.  Runs concurrently
    with up to 10 in-flight requests.
    """
    import httpx  # already in venv via xelo dependency

    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        # 1. Get recursive tree
        for default_branch in (branch, "master"):
            r = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/"
                f"{default_branch}?recursive=1"
            )
            if r.status_code == 200:
                branch = default_branch
                break
        else:
            raise RuntimeError(
                f"GitHub tree fetch failed for {owner}/{repo} "
                f"(tried '{branch}' and 'master'): {r.status_code} {r.text[:200]}"
            )

        all_blobs = [i for i in r.json().get("tree", []) if i.get("type") == "blob"]
        tree_items: list[dict[str, Any]] = [
            item for item in all_blobs
            if Path(item["path"]).suffix.lower() in _SCAN_EXTENSIONS
            and item.get("size", 0) < 200_000  # skip files > 200 kB
            and not any(
                part in _SKIP_DIRS
                for part in Path(item["path"]).parts
            )
            and not any(
                item["path"].startswith(pfx)
                for pfx in _SKIP_PATH_PREFIXES
            )
        ][:max_files]
        _log.info(
            "[github-fetch] %s/%s@%s: %d total blobs, %d scannable after filtering (cap=%d)",
            owner, repo, branch, len(all_blobs), len(tree_items), max_files,
        )

        # 2. Fetch blobs concurrently (semaphore = 10 concurrent requests)
        sem = asyncio.Semaphore(10)

        async def _fetch_blob(item: dict[str, Any]) -> tuple[str, str] | None:
            async with sem:
                try:
                    br = await client.get(
                        f"https://api.github.com/repos/{owner}/{repo}"
                        f"/git/blobs/{item['sha']}"
                    )
                    if br.status_code != 200:
                        return None
                    data = br.json()
                    import base64
                    content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
                    return (item["path"], content)
                except Exception:
                    return None

        results = await asyncio.gather(*[_fetch_blob(i) for i in tree_items])
        fetched = [r for r in results if r is not None]
        _log.info(
            "[github-fetch] fetched %d/%d blobs successfully",
            len(fetched), len(tree_items),
        )
        return fetched


def _fetch_github_to_tmpdir(
    url: str,
    token: str | None = None,
    max_files: int = _GITHUB_MAX_FILES,
) -> tuple[str, Any]:
    """Fetch a GitHub repo into a temporary directory and return the path.

    Parameters
    ----------
    url:
        GitHub repository URL (https://github.com/owner/repo[/tree/branch]).
    token:
        GitHub personal access token (raises rate limit from 60 to 5000 req/h).
        Defaults to the ``GITHUB_TOKEN`` environment variable.
    max_files:
        Maximum number of source files to fetch (default 500).

    Returns
    -------
    ``(tmpdir_path, cleanup_fn)`` — call ``cleanup_fn()`` when done.
    The caller is responsible for cleanup even if an exception occurs.
    """
    resolved_token = token or os.getenv("GITHUB_TOKEN") or None
    owner, repo, branch = _parse_github_url(url)
    _log.info(
        "fetching GitHub repo %s/%s (branch=%s, max_files=%d)",
        owner, repo, branch, max_files,
    )

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # Already inside an event loop (e.g. Jupyter / async test runner) —
        # run the coroutine in a separate thread to avoid "loop is running" error.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                _async_github_fetch(owner, repo, branch, resolved_token, max_files),
            )
            files = future.result(timeout=120)
    else:
        files = asyncio.run(
            _async_github_fetch(owner, repo, branch, resolved_token, max_files)
        )

    tmpdir = tempfile.mkdtemp(prefix="policy_assess_github_")

    def _cleanup() -> None:
        shutil.rmtree(tmpdir, ignore_errors=True)

    for rel_path, content in files:
        dest = Path(tmpdir) / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_text(content, encoding="utf-8")
        except OSError:
            pass

    _log.info(
        "fetched %d files from %s/%s → %s",
        len(files), owner, repo, tmpdir,
    )
    return tmpdir, _cleanup


# ---------------------------------------------------------------------------
# LLM wrapper  (EXPERIMENTAL — will be promoted to a ToolPlugin in a future
#               release with async support and a pluggable interface)
# ---------------------------------------------------------------------------

class _LLMClient:
    """Thin synchronous wrapper around *litellm* for policy assessment.

    Supports any model string accepted by litellm — see
    https://docs.litellm.ai/docs/providers for the full list, e.g.
    ``"gpt-4o"``, ``"anthropic/claude-3-5-sonnet-20241022"``,
    ``"ollama/mistral"``.

    EXPERIMENTAL: this class is private to this plugin module.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        api_base: str | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.api_base = api_base

    def complete_structured(
        self,
        system: str,
        user: str,
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Call the LLM and parse its response as a JSON dict.

        Parameters
        ----------
        system:
            System prompt establishing the analyst persona and control context.
        user:
            User turn containing evidence sections and the assessment task.
        response_schema:
            JSON Schema dict appended to the user prompt as a structural hint.
            ``response_format=json_object`` is used to improve adherence.

        Returns
        -------
        Parsed JSON dict, or ``{}`` if the response cannot be decoded.

        Raises
        ------
        RuntimeError
            If litellm is unavailable or the LLM call itself fails (network,
            auth, quota, etc.).
        """
        try:
            import litellm  # lazy — optional production dependency
        except ImportError as exc:
            raise RuntimeError(
                "litellm is required for policy assessment. "
                "Install it with: pip install litellm"
            ) from exc

        schema_hint = json.dumps(response_schema, indent=2)
        full_user = (
            f"{user}\n\n"
            "Respond with valid JSON **only**, no prose, strictly matching "
            f"this schema:\n{schema_hint}"
        )

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": full_user},
            ],
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base

        try:
            response = litellm.completion(**kwargs)
        except Exception as exc:
            raise RuntimeError(f"LLM call failed ({self.model}): {exc}") from exc

        raw: str = response.choices[0].message.content or ""
        # Strip markdown code fences when present
        raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
        raw = re.sub(r"\s*```$", "", raw)
        try:
            parsed: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            _log.warning(
                "LLM returned unparseable JSON; returning {}. Content: %r",
                raw[:200],
            )
            return {}

        return parsed


# ---------------------------------------------------------------------------
# Repo scanner  (module-private)
# ---------------------------------------------------------------------------

def _scan_for_keywords(
    repo_path: str,
    keywords: list[str],
    max_hits: int = 25,
) -> list[dict[str, Any]]:
    """Walk *repo_path* and collect lines matching any keyword.

    Parameters
    ----------
    repo_path:
        Absolute or relative path to the repository root.
    keywords:
        Terms from ``evidence_queries.keywords``, compiled into one
        ``re.IGNORECASE`` alternation pattern.
    max_hits:
        Cap on the total number of lines returned (default 25).

    Returns
    -------
    List of ``{file, line, content, keyword}`` dicts using paths relative to
    *repo_path*.  Empty list if *keywords* is empty or the path does not
    exist.
    """
    if not keywords:
        _log.debug("[repo-scan] no keywords — skipping scan")
        return []
    if not os.path.isdir(repo_path):
        _log.warning("[repo-scan] repo_path is not a directory: %r", repo_path)
        return []

    _log.info(
        "[repo-scan] scanning %r for %d keyword(s): %s",
        repo_path,
        len(keywords),
        ", ".join(repr(k) for k in keywords[:10])
        + (" …" if len(keywords) > 10 else ""),
    )

    pattern = re.compile(
        "|".join(re.escape(k) for k in keywords),
        re.IGNORECASE,
    )

    hits: list[dict[str, Any]] = []
    base = Path(repo_path)
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune unwanted directories in-place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for filename in filenames:
            if Path(filename).suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            full = Path(dirpath) / filename
            try:
                rel = str(full.relative_to(base))
            except ValueError:
                rel = str(full)
            # Normalise to forward slashes for prefix matching on all platforms
            rel_fwd = rel.replace(os.sep, "/")
            if any(rel_fwd.startswith(pfx) for pfx in _SKIP_PATH_PREFIXES):
                continue
            try:
                text = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            files_scanned += 1
            for lineno, line in enumerate(text.splitlines(), start=1):
                m = pattern.search(line)
                if m:
                    hits.append({
                        "file":    rel,
                        "line":    lineno,
                        "content": line.strip()[:200],
                        "keyword": m.group(0),
                    })
                    if len(hits) >= max_hits:
                        _log.info(
                            "[repo-scan] hit cap (%d) reached in %d files; last match in %s",
                            max_hits, files_scanned, rel,
                        )
                        return hits

    _log.info(
        "[repo-scan] scanned %d file(s), found %d hit(s)",
        files_scanned, len(hits),
    )
    if hits:
        unique_files = sorted({h['file'] for h in hits})
        _log.info("[repo-scan] matched files: %s", ", ".join(unique_files[:10]))
    return hits


# ---------------------------------------------------------------------------
# AIBOM evidence helpers
# ---------------------------------------------------------------------------

def _extract_aibom_evidence(
    control: dict[str, Any],
    sbom: dict[str, Any],
) -> dict[str, Any]:
    """Extract AIBOM signal relevant to *control*.

    Returns
    -------
    dict with keys:
        matched_nodes    — list of node dicts matching aibom_node_types
        metadata_values  — resolved aibom_metadata_fields paths → their values
        edge_count       — edges whose source or target is a matched node id
        found_types      — component_type values actually found
        missing_types    — expected types absent from matched nodes
    """
    eq = control.get("evidence_queries") or {}
    wanted_types: list[str] = eq.get("aibom_node_types") or []
    field_paths: list[str]  = eq.get("aibom_metadata_fields") or []

    nodes:   list[dict[str, Any]] = sbom.get("nodes") or []
    edges:   list[dict[str, Any]] = sbom.get("edges") or []
    summary: dict[str, Any]       = sbom.get("summary") or {}

    wanted_set = set(wanted_types)
    matched_nodes = (
        [n for n in nodes if n.get("component_type", "") in wanted_set]
        if wanted_set else []
    )

    matched_ids = {n.get("id") for n in matched_nodes if n.get("id")}
    relevant_edges = [
        e for e in edges
        if e.get("source") in matched_ids or e.get("target") in matched_ids
    ]

    # Resolve each requested metadata field path
    metadata_values: dict[str, Any] = {}
    for path in field_paths:
        if path.startswith("summary."):
            key = path.split(".", 1)[1]
            val = summary.get(key)
            if val is not None:
                metadata_values[path] = val
        elif path.startswith("metadata."):
            key = path.split(".", 1)[1]
            vals = [
                {"node": n.get("name", ""), "value": (n.get("metadata") or {}).get(key)}
                for n in matched_nodes
                if (n.get("metadata") or {}).get(key) is not None
            ]
            if vals:
                metadata_values[path] = vals

    found_types   = sorted({n.get("component_type", "") for n in matched_nodes})
    missing_types = sorted(wanted_set - set(found_types))

    return {
        "matched_nodes": [
            {
                "name":           n.get("name", ""),
                "component_type": n.get("component_type", ""),
                "confidence":     n.get("confidence", 0.0),
            }
            for n in matched_nodes
        ],
        "metadata_values": metadata_values,
        "edge_count":      len(relevant_edges),
        "found_types":     found_types,
        "missing_types":   missing_types,
    }


# ---------------------------------------------------------------------------
# LLM response schema (used as a structural hint in the prompt)
# ---------------------------------------------------------------------------

_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["status", "title", "confidence", "evidence", "remediation"],
    "properties": {
        "status": {
            "type": "string",
            "enum": ["GAP", "COVERED"],
            "description": "Whether this control is met (COVERED) or not (GAP).",
        },
        "title": {
            "type": "string",
            "description": "Short finding title, 8 words or fewer.",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "0.0 = no evidence at all, 1.0 = fully confirmed.",
        },
        "evidence_summary": {
            "type": "string",
            "description": "For GAP: a sentence describing what evidence is absent.",
        },
        "evidence": {
            "type": "array",
            "description": (
                "For COVERED: list of objects {ref, note} citing each evidence source. "
                "Use ref='aibom://nodes/TYPE/name' for AIBOM nodes, "
                "ref='path/to/file.py:42' for repo hits. "
                "For GAP: list of plain strings describing missing evidence."
            ),
            "items": {
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["ref", "note"],
                        "properties": {
                            "ref":  {"type": "string"},
                            "note": {"type": "string"},
                        },
                    },
                    {"type": "string"},
                ]
            },
        },
        "remediation": {
            "type": "string",
            "description": (
                "Specific, actionable remediation steps for this repository. "
                "Reference actual component names and file paths visible in the evidence."
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(
    control: dict[str, Any],
    aibom_ev: dict[str, Any],
    repo_hits: list[dict[str, Any]],
    framework: str,
) -> tuple[str, str]:
    """Return ``(system, user)`` prompt strings for one control assessment."""
    cid       = control.get("control_id", "")
    name      = control.get("name", "")
    desc      = control.get("description", "")
    category  = control.get("category", "")
    severity  = control.get("severity", "MEDIUM")
    wtlf      = control.get("what_to_look_for") or []
    mitig     = control.get("typical_mitigations") or []
    inv       = control.get("inventory_coverage") or {}
    inv_lvl   = inv.get("level", "partial")
    inv_notes = inv.get("notes") or []

    # ── System prompt ─────────────────────────────────────────────────────
    wtlf_bullets  = "\n".join(f"  - {item}" for item in wtlf)
    mitig_bullets = "\n".join(f"  - {item}" for item in mitig)
    inv_notes_txt = (
        "\n".join(f"  * {n}" for n in inv_notes)
        if inv_notes else "  (none)"
    )

    system = (
        f"You are a security compliance analyst evaluating an AI system "
        f"against the {framework} framework.\n\n"
        f"Control: {cid} — {name}\n"
        f"Category: {category} | Severity: {severity}\n\n"
        f"Description:\n{desc}\n\n"
        f"What to look for:\n{wtlf_bullets or '  (no guidance provided)'}\n\n"
        f"Typical mitigations:\n{mitig_bullets or '  (no mitigations listed)'}\n\n"
        f"AIBOM inventory coverage level: {inv_lvl}\n"
        f"Coverage notes:\n{inv_notes_txt}\n\n"
        "Your task: assess whether the provided evidence confirms this control "
        "is COVERED or reveals a GAP.  Be conservative — only mark COVERED "
        "when there is direct, concrete evidence.  Set confidence proportionally "
        "to the breadth and specificity of the evidence."
    )

    # ── User prompt ───────────────────────────────────────────────────────
    matched       = aibom_ev.get("matched_nodes") or []
    meta_vals     = aibom_ev.get("metadata_values") or {}
    missing_types = aibom_ev.get("missing_types") or []
    found_types   = aibom_ev.get("found_types") or []
    edge_count    = aibom_ev.get("edge_count", 0)

    if matched:
        node_rows = "\n".join(
            f"  - [{n['component_type']}] {n['name']}  "
            f"(confidence={n.get('confidence', '?')})"
            for n in matched
        )
    else:
        node_rows = "  (none found)"

    if meta_vals:
        meta_rows = "\n".join(
            f"  - {k}: {json.dumps(v, default=str)}"
            for k, v in meta_vals.items()
        )
    else:
        meta_rows = "  (no relevant metadata fields populated)"

    missing_txt = (
        f"  Missing node types: {', '.join(missing_types)}"
        if missing_types else
        "  All expected node types are present."
    )

    aibom_section = (
        "## AIBOM Evidence\n"
        f"Matched nodes: {len(matched)} "
        f"(types found: {', '.join(found_types) or 'none'})\n"
        f"{node_rows}\n\n"
        f"Resolved metadata fields:\n{meta_rows}\n\n"
        f"{missing_txt}\n"
        f"  Relevant edges between matched nodes: {edge_count}"
    )

    if repo_hits:
        hit_rows = "\n".join(
            f"  [{h['file']}:{h['line']}] {h['content']}"
            for h in repo_hits
        )
        repo_section = (
            f"## Repository Evidence ({len(repo_hits)} keyword hit(s))\n"
            f"{hit_rows}"
        )
    else:
        repo_section = (
            "## Repository Evidence\n"
            "  (no keyword hits found in this repository)"
        )

    task = (
        "## Assessment Task\n"
        "Based solely on the evidence above:\n"
        "1. Determine STATUS: COVERED (requirement met) or GAP (not met / unclear).\n"
        "2. Set CONFIDENCE between 0.0 (no evidence) and 1.0 (fully confirmed).\n"
        "3. List EVIDENCE:\n"
        "   - If COVERED: each item must be an object "
        '{ref: "aibom://nodes/TYPE/name"  OR  "path/file.py:42", '
        'note: "why this confirms the control"}.\n'
        "   - If GAP: each item must be a plain string describing "
        "what evidence is absent.\n"
        "4. Write REMEDIATION specific to this repository — reference actual "
        "component names and file paths visible in the evidence above.\n"
        "5. Optionally add EVIDENCE_SUMMARY (one sentence) for GAP status."
    )

    user = f"{aibom_section}\n\n{repo_section}\n\n{task}"
    return system, user


# ---------------------------------------------------------------------------
# Overall status helper
# ---------------------------------------------------------------------------

_HIGH_SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH"})


def _compute_overall_status(control_results: list[dict[str, Any]]) -> str:
    """Derive plugin-level status from per-control assessment results.

    ``failed``  — ≥1 GAP at CRITICAL/HIGH severity with confidence ≥ 0.5
    ``warning`` — ≥1 GAP at any other severity (or low-confidence high-sev)
    ``ok``      — all controls COVERED
    """
    any_gap = False
    for cr in control_results:
        result = cr.get("result") or {}
        if result.get("status") != "GAP":
            continue
        any_gap = True
        sev  = str(cr.get("severity", "")).upper()
        conf = float(result.get("confidence", 0.0))
        if sev in _HIGH_SEVERITIES and conf >= 0.5:
            return "failed"
    return "warning" if any_gap else "ok"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class PolicyAssessmentPlugin(ToolPlugin):
    """Assess SBOM compliance against a NuGuard Standard policy file.

    Config keys
    -----------
    policy_file : str
        Required. Path to a ``*_nuguard_standard.json`` policy file.
    llm_model : str
        Required. litellm model string, e.g. ``"gpt-4o"`` or
        ``"anthropic/claude-3-5-sonnet-20241022"``.
    repo_path : str
        Optional. Repository root for keyword scanning (default: CWD).
    llm_api_key : str | None
        Optional. Overrides ``OPENAI_API_KEY`` / ``LITELLM_API_KEY`` env vars.
    llm_api_base : str | None
        Optional. Custom API base URL (for proxies or local models).
    max_repo_hits : int
        Optional. Maximum keyword-match lines returned per control (default 25).
    """

    name = "policy_assess"

    def run(self, sbom: dict[str, Any], config: dict[str, Any]) -> ToolResult:
        # ── validate required config ──────────────────────────────────────
        policy_file: str = config.get("policy_file", "")
        if not policy_file:
            raise ValueError("policy_assess: 'policy_file' is required in config")

        llm_model: str = config.get("llm_model", "")
        if not llm_model:
            raise ValueError("policy_assess: 'llm_model' is required in config")

        repo_path:     str      = config.get("repo_path") or os.getcwd()
        llm_api_key:   str | None = config.get("llm_api_key") or None
        llm_api_base:  str | None = config.get("llm_api_base") or None
        max_repo_hits: int = int(config.get("max_repo_hits", 25))
        github_token:  str | None = (
            config.get("github_token")
            or os.getenv("GITHUB_TOKEN")
            or None
        )

        # ── load policy ───────────────────────────────────────────────────
        try:
            with open(policy_file, encoding="utf-8") as fh:
                policy = json.load(fh)
        except FileNotFoundError:
            raise ValueError(
                f"policy_assess: policy file not found: {policy_file!r}"
            )
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"policy_assess: invalid JSON in policy file: {exc}"
            )

        framework:  str               = policy.get("framework", "Unknown Framework")
        fw_version: str               = policy.get("framework_version", "")
        controls:   list[dict[str, Any]] = policy.get("controls") or []

        # ── instantiate LLM client ────────────────────────────────────────
        llm = _LLMClient(
            model=llm_model,
            api_key=llm_api_key,
            api_base=llm_api_base,
        )

        # ── resolve repo path (supports GitHub URLs and cached_files.json) ──
        _cleanup_fn = None
        repo_source = "local"
        if _is_github_url(repo_path):
            repo_source = "github"
            _log.info("repo_path is a GitHub URL — fetching to tmpdir")
            repo_path, _cleanup_fn = _fetch_github_to_tmpdir(
                repo_path, github_token
            )
        elif _is_cached_files_json(repo_path):
            repo_source = "cached_json"
            _log.info("repo_path is a cached_files.json — loading into tmpdir")
            repo_path, _cleanup_fn = _load_cached_files_to_tmpdir(repo_path)

        # ── assess each control ───────────────────────────────────────────
        control_results: list[dict[str, Any]] = []
        try:
            for control in controls:
                _log.info("assessing %s / %s", framework, control.get("control_id", "?"))
                cr = self._assess_control(
                    control, sbom, llm, repo_path, max_repo_hits, framework
                )
                control_results.append(cr)
        finally:
            if _cleanup_fn is not None:
                _cleanup_fn()

        # ── overall status + summary ──────────────────────────────────────
        status  = _compute_overall_status(control_results)
        covered = sum(
            1 for cr in control_results
            if (cr.get("result") or {}).get("status") == "COVERED"
        )
        gap = len(control_results) - covered
        pct = (
            round(covered / len(control_results) * 100, 1)
            if control_results else 0.0
        )

        message = (
            f"{framework}: {covered}/{len(control_results)} controls COVERED "
            f"({pct}%) — status={status}"
        )
        _log.info(message)

        return ToolResult(
            status=status,
            tool=self.name,
            message=message,
            details={
                "framework":         framework,
                "framework_version": fw_version,
                "policy_file":       policy_file,
                "repo_path":         config.get("repo_path") or os.getcwd(),
                "repo_source":       repo_source,
                "llm_model":         llm_model,
                "assessed_at":       datetime.now(timezone.utc).isoformat(),
                "controls":          control_results,
                "summary": {
                    "total":        len(control_results),
                    "covered":      covered,
                    "gap":          gap,
                    "coverage_pct": pct,
                },
            },
        )

    def _assess_control(
        self,
        control: dict[str, Any],
        sbom: dict[str, Any],
        llm: _LLMClient,
        repo_path: str,
        max_repo_hits: int,
        framework: str,
    ) -> dict[str, Any]:
        control_id = control.get("control_id", "?")
        inv_lvl = (control.get("inventory_coverage") or {}).get("level", "partial")

        # Phase 1 — AIBOM inspection
        aibom_ev = _extract_aibom_evidence(control, sbom)
        _log.info(
            "[%s] Phase-1 AIBOM: %d matched node(s) [types: %s], %d metadata value(s)%s",
            control_id,
            len(aibom_ev.get("matched_nodes") or []),
            ", ".join(aibom_ev.get("found_types") or []) or "none",
            len(aibom_ev.get("metadata_values") or {}),
            (f"; MISSING types: {aibom_ev['missing_types']}"
             if aibom_ev.get("missing_types") else ""),
        )

        # Phase 2 — Repo scan  (skip when AIBOM alone gives full coverage)
        if inv_lvl == "full":
            _log.info("[%s] Phase-2 REPO: skipped (inventory_coverage.level=full)", control_id)
            repo_hits: list[dict[str, Any]] = []
        else:
            keywords = (control.get("evidence_queries") or {}).get("keywords") or []
            _log.info(
                "[%s] Phase-2 REPO: %d keyword(s) to scan (coverage_level=%s)",
                control_id, len(keywords), inv_lvl,
            )
            repo_hits = _scan_for_keywords(repo_path, keywords, max_repo_hits)
            _log.info(
                "[%s] Phase-2 REPO: %d hit(s) in %d unique file(s)",
                control_id,
                len(repo_hits),
                len({h["file"] for h in repo_hits}),
            )

        # Phase 3 — LLM synthesis
        _log.info("[%s] Phase-3 LLM: calling %r …", control_id, llm.model)
        system, user = _build_prompt(control, aibom_ev, repo_hits, framework)
        llm_result   = llm.complete_structured(system, user, _RESPONSE_SCHEMA)
        _log.info(
            "[%s] Phase-3 LLM: status=%s confidence=%.2f title=%r",
            control_id,
            llm_result.get("status", "?"),
            float(llm_result.get("confidence", 0.0)),
            llm_result.get("title", ""),
        )

        return {
            "control_id":               control_id,
            "name":                     control.get("name", ""),
            "category":                 control.get("category", ""),
            "severity":                 control.get("severity", "MEDIUM"),
            "inventory_coverage_level": inv_lvl,
            "result":                   llm_result,
            "aibom_evidence_count":     len(aibom_ev.get("matched_nodes") or []),
            "repo_hits_count":          len(repo_hits),
        }
