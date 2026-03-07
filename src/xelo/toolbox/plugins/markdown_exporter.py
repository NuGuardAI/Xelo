"""Markdown export plugin.

Renders the SBOM as a human-readable Markdown report, suitable for
inclusion in pull requests, wikis, and security reviews.

Output sections
---------------
- Header with target name, generation timestamp, and schema version
- Summary table (node/dep counts, data classification, frameworks, …)
- AI Components table (name, component_type, confidence)
- Dependencies table (name, version, group, license)
- Node Type Breakdown (from summary.node_counts, if present)
"""
from __future__ import annotations

import logging
from typing import Any

from xelo.toolbox.models import ToolResult
from xelo.toolbox.plugin_base import ToolPlugin

_log = logging.getLogger("toolbox.plugins.markdown")


# ── Markdown helpers ──────────────────────────────────────────────────────────

def _esc(val: Any) -> str:
    """Escape pipe characters so they don't break Markdown table cells."""
    return str(val).replace("|", "\\|")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    header_row = "| " + " | ".join(headers) + " |"
    sep_row    = "| " + " | ".join("---" for _ in headers) + " |"
    data_rows  = [
        "| " + " | ".join(_esc(c) for c in row) + " |"
        for row in rows
    ]
    return "\n".join([header_row, sep_row] + data_rows)


# ── Plugin ────────────────────────────────────────────────────────────────────

class MarkdownExporterPlugin(ToolPlugin):
    name = "markdown_export"

    def run(self, sbom: dict[str, Any], config: dict[str, Any]) -> ToolResult:
        target     = sbom.get("target") or "unknown"
        generated  = sbom.get("generated_at") or ""
        schema_ver = sbom.get("schema_version") or ""
        nodes      = sbom.get("nodes") or []
        deps       = sbom.get("deps") or []
        summary    = sbom.get("summary") or {}

        _log.info(
            "generating Markdown report for '%s' (%d node(s), %d dep(s))",
            target, len(nodes), len(deps),
        )

        lines: list[str] = []

        # ── Header ──────────────────────────────────────────────────────────
        lines += [f"# SBOM Report: {target}", ""]
        if generated:
            lines += [f"**Generated:** {generated}  "]
        if schema_ver:
            lines += [f"**Schema version:** {schema_ver}  "]
        lines += [""]

        # ── Summary ─────────────────────────────────────────────────────────
        lines += ["## Summary", ""]
        summary_rows: list[list[Any]] = [
            ["AI nodes",     len(nodes)],
            ["Dependencies", len(deps)],
        ]
        dc = summary.get("data_classification") or []
        if dc:
            summary_rows.append(["Data classification", ", ".join(dc)])
        classified_tables = summary.get("classified_tables") or []
        if classified_tables:
            summary_rows.append(["Classified tables", ", ".join(classified_tables)])
        use_case = summary.get("use_case")
        if use_case:
            summary_rows.append(["Use case", use_case])
        frameworks = summary.get("frameworks") or []
        if frameworks:
            summary_rows.append(["Frameworks", ", ".join(frameworks)])
        modalities = summary.get("modalities") or []
        if modalities:
            summary_rows.append(["Modalities", ", ".join(modalities)])
        lines += [_table(["Field", "Value"], summary_rows), ""]

        # ── AI Components ────────────────────────────────────────────────────
        if nodes:
            lines += ["## AI Components", ""]
            node_rows: list[list[Any]] = [
                [
                    n.get("name", ""),
                    n.get("component_type", ""),
                    f"{n['confidence']:.0%}" if isinstance(n.get("confidence"), float) else "",
                ]
                for n in nodes
            ]
            lines += [_table(["Name", "Type", "Confidence"], node_rows), ""]

        # ── Dependencies ─────────────────────────────────────────────────────
        if deps:
            lines += ["## Dependencies", ""]
            dep_rows: list[list[Any]] = [
                [
                    d.get("name", ""),
                    d.get("version_spec") or d.get("version") or "",
                    d.get("group", ""),
                    d.get("license", ""),
                ]
                for d in deps
            ]
            lines += [_table(["Name", "Version", "Group", "License"], dep_rows), ""]

        # ── Node Type Breakdown ───────────────────────────────────────────────
        node_counts: dict[str, Any] = summary.get("node_counts") or {}
        if node_counts:
            lines += ["## Node Type Breakdown", ""]
            count_rows: list[list[Any]] = [
                [k, v] for k, v in sorted(node_counts.items())
            ]
            lines += [_table(["Type", "Count"], count_rows), ""]

        markdown = "\n".join(lines)
        _log.debug("generated %d character(s) of Markdown", len(markdown))

        return ToolResult(
            status="ok",
            tool=self.name,
            message=f"Markdown report generated ({len(nodes)} node(s), {len(deps)} dep(s))",
            details={"markdown": markdown},
        )
