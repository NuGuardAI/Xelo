"""MITRE ATLAS annotation plugin for Xelo AI SBOMs.

Runs two passes against the SBOM and annotates each finding with one or more
MITRE ATLAS v2 techniques that an attacker could exploit given the detected
weakness:

Pass 1 — VLA signal mapping
  Runs the VulnerabilityScannerPlugin with ``provider=xelo-rules`` (offline,
  no network required).  Every VLA-xxx finding is enriched with an ``atlas``
  block containing matching techniques from the static VLA → ATLAS mapping
  table in ``_atlas_data.py``.

Pass 2 — Native ATLAS graph checks
  Directly inspects the SBOM graph for additional structural patterns that
  map to ATLAS techniques but are not fully covered by any single VLA rule:

  ATLAS-NC-001  External MODEL without integrity hash         → AML.T0010, T0048
  ATLAS-NC-002  Writable DATASTORE reachable by unguarded model/agent → AML.T0020
  ATLAS-NC-003  MODEL–DEPLOYMENT path without AUTH node       → AML.T0035
  ATLAS-NC-004  AGENT or TOOL with outbound external-API capability → AML.T0036

Output ``details`` schema::

    {
      "atlas_version":       "v2",
      "basis":               "static",
      "total_findings":      12,
      "techniques_identified": ["AML.T0051", ...],
      "tactics_covered":     ["Defense Evasion", ...],
      "confidence_breakdown": {"HIGH": 5, "MEDIUM": 4, "LOW": 1},
      "findings": [
        {
          "rule_id":     "VLA-001",
          "severity":    "CRITICAL",
          "title":       "...",
          "description": "...",
          "affected":    [...],
          "remediation": "...",
          "source":      "xelo-rules",
          "atlas": {
            "atlas_version": "v2",
            "techniques": [
              {
                "technique_id":   "AML.T0051",
                "technique_name": "LLM Jailbreak",
                "tactic_id":      "AML.TA0005",
                "tactic_name":    "Defense Evasion",
                "atlas_url":      "https://atlas.mitre.org/techniques/AML.T0051",
                "confidence":     "HIGH",
                "basis":          "static",
                "mitigations": [
                  {
                    "mitigation_id":   "AML.M0015",
                    "mitigation_name": "Adversarial Input Detection",
                    "mitigation_url":  "https://atlas.mitre.org/mitigations/AML.M0015"
                  }
                ]
              }
            ]
          }
        },
        ...
      ]
    }
"""
from __future__ import annotations

import logging
from typing import Any, cast

from xelo_toolbox.models import ToolResult
from xelo_toolbox.plugin_base import ToolPlugin
from xelo_toolbox.plugins._atlas_data import (
    ATLAS_VERSION,
    MITIGATIONS,
    NATIVE_CHECKS,
    OUTBOUND_KEYWORDS,
    TACTICS,
    TECHNIQUES,
    VLA_TO_ATLAS,
    EXTERNAL_PROVIDERS,
)

_log = logging.getLogger("toolbox.plugins.atlas")


class AtlasAnnotatorPlugin(ToolPlugin):
    """Annotate SBOM findings with MITRE ATLAS v2 technique IDs."""

    name = "atlas_annotate"

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def run(self, sbom: dict[str, Any], config: dict[str, Any]) -> ToolResult:  # noqa: ARG002
        """Annotate *sbom* with ATLAS technique mappings.

        *config* is currently unused (all analysis is static and offline).
        """
        _log.info("ATLAS annotation starting (atlas_version=%s, basis=static)", ATLAS_VERSION)

        # ------------------------------------------------------------------
        # Pass 1 — run structural VLA rules and annotate findings
        # ------------------------------------------------------------------
        vla_findings = self._run_vla_pass(sbom)
        _log.debug("Pass 1: %d VLA finding(s) produced", len(vla_findings))

        # ------------------------------------------------------------------
        # Pass 2 — native ATLAS graph checks
        # ------------------------------------------------------------------
        native_findings = self._run_native_pass(sbom)
        _log.debug("Pass 2: %d native ATLAS finding(s) produced", len(native_findings))

        all_findings = vla_findings + native_findings
        _log.info("ATLAS annotation complete: %d total finding(s)", len(all_findings))

        # ------------------------------------------------------------------
        # Aggregate statistics
        # ------------------------------------------------------------------
        technique_ids: list[str] = []
        tactic_names: list[str] = []
        confidence_breakdown: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for f in all_findings:
            atlas_block = f.get("atlas", {})
            for t in atlas_block.get("techniques", []):
                tid = t.get("technique_id", "")
                if tid and tid not in technique_ids:
                    technique_ids.append(tid)
                tname = t.get("tactic_name", "")
                if tname and tname not in tactic_names:
                    tactic_names.append(tname)
                conf = t.get("confidence", "").upper()
                if conf in confidence_breakdown:
                    confidence_breakdown[conf] += 1

        status = "warning" if all_findings else "ok"
        message = (
            f"{len(all_findings)} ATLAS-annotated finding(s) across "
            f"{len(technique_ids)} unique technique(s)"
            if all_findings
            else "No ATLAS findings detected"
        )

        return ToolResult(
            status=status,
            tool=self.name,
            message=message,
            details={
                "atlas_version":        ATLAS_VERSION,
                "basis":                "static",
                "total_findings":       len(all_findings),
                "techniques_identified": technique_ids,
                "tactics_covered":      tactic_names,
                "confidence_breakdown": confidence_breakdown,
                "findings":             all_findings,
            },
        )

    # ------------------------------------------------------------------ #
    # Pass 1 helpers                                                       #
    # ------------------------------------------------------------------ #

    def _run_vla_pass(self, sbom: dict[str, Any]) -> list[dict[str, Any]]:
        """Run structural VLA rules then annotate each finding with ATLAS techniques."""
        # Lazy import to avoid circular dependency at module level
        from xelo_toolbox.plugins.vulnerability import VulnerabilityScannerPlugin  # noqa: PLC0415

        scanner = VulnerabilityScannerPlugin()
        result = scanner.run(sbom, {"provider": "xelo-rules"})

        raw_findings: list[dict[str, Any]] = list(result.details.get("findings", []) or [])
        annotated: list[dict[str, Any]] = []

        for finding in raw_findings:
            rule_id = finding.get("rule_id", "")
            technique_tuples = VLA_TO_ATLAS.get(rule_id, [])
            if technique_tuples:
                finding["atlas"] = _build_atlas_block(technique_tuples)
                _log.debug(
                    "annotated %s → %d ATLAS technique(s)",
                    rule_id, len(technique_tuples),
                )
            else:
                # finding has no mapping; include without an atlas block
                _log.debug("no ATLAS mapping for rule_id=%r", rule_id)
            annotated.append(finding)

        return annotated

    # ------------------------------------------------------------------ #
    # Pass 2 helpers                                                       #
    # ------------------------------------------------------------------ #

    def _run_native_pass(self, sbom: dict[str, Any]) -> list[dict[str, Any]]:
        """Run native ATLAS graph checks against the raw SBOM."""
        nodes: list[dict[str, Any]] = list(sbom.get("nodes") or [])
        edges: list[dict[str, Any]] = list(sbom.get("edges") or [])

        findings: list[dict[str, Any]] = []

        # Build fast lookup structures
        nodes_by_id = {n.get("id", ""): n for n in nodes}
        node_types_by_id: dict[str, str] = {
            n.get("id", ""): (n.get("component_type") or "").upper()
            for n in nodes
        }
        # adjacency: source → set of target ids (directed)
        adjacency: dict[str, set[str]] = {}
        for edge in edges:
            src = edge.get("source") or edge.get("from") or ""
            tgt = edge.get("target") or edge.get("to") or ""
            if src and tgt:
                adjacency.setdefault(src, set()).add(tgt)

        type_sets: dict[str, set[str]] = {}
        for nid, ntype in node_types_by_id.items():
            type_sets.setdefault(ntype, set()).add(nid)

        findings += self._check_nc001_external_model_no_hash(
            nodes, type_sets
        )
        findings += self._check_nc002_unguarded_datastore(
            type_sets, adjacency, node_types_by_id
        )
        findings += self._check_nc003_model_deployment_no_auth(
            type_sets, adjacency, node_types_by_id, nodes_by_id
        )
        findings += self._check_nc004_outbound_agent_tool(
            nodes, type_sets
        )

        return findings

    # NC-001 ----------------------------------------------------------------

    def _check_nc001_external_model_no_hash(
        self,
        nodes: list[dict[str, Any]],
        type_sets: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        check = NATIVE_CHECKS[0]  # ATLAS-NC-001
        affected: list[str] = []

        for nid in type_sets.get("MODEL", set()):
            node = next((n for n in nodes if n.get("id") == nid), {})
            name = node.get("name", nid)
            provider = (node.get("provider") or node.get("metadata", {}).get("provider") or "").lower()
            extras = (node.get("metadata") or {}).get("extras") or {}
            has_external = any(p in provider for p in EXTERNAL_PROVIDERS)
            has_hash = bool(extras.get("integrity_hash"))
            if has_external and not has_hash:
                affected.append(name)
                _log.debug("NC-001: external model '%s' has no integrity_hash", name)

        if not affected:
            return []

        return [_native_finding(check, affected)]

    # NC-002 ----------------------------------------------------------------

    def _check_nc002_unguarded_datastore(
        self,
        type_sets: dict[str, set[str]],
        adjacency: dict[str, set[str]],
        node_types_by_id: dict[str, str],
    ) -> list[dict[str, Any]]:
        check = NATIVE_CHECKS[1]  # ATLAS-NC-002
        affected: list[str] = []

        agent_model_ids = type_sets.get("AGENT", set()) | type_sets.get("MODEL", set())
        guardrail_ids = type_sets.get("GUARDRAIL", set())
        datastore_ids = type_sets.get("DATASTORE", set())

        if not datastore_ids or not agent_model_ids:
            return []

        # For each agent/model, check if it can reach a datastore WITHOUT
        # passing through any guardrail node
        for src in agent_model_ids:
            # BFS: can we reach a datastore?
            visited: set[str] = {src}
            queue = list(adjacency.get(src, set()))
            reached_ds: set[str] = set()
            guarded = False

            while queue:
                nid = queue.pop()
                if nid in visited:
                    continue
                visited.add(nid)
                ntype = node_types_by_id.get(nid, "")
                if ntype == "GUARDRAIL":
                    guarded = True
                    break
                if nid in datastore_ids:
                    reached_ds.add(nid)
                queue.extend(adjacency.get(nid, set()) - visited)

            if reached_ds and not guarded:
                affected.extend(reached_ds)
                _log.debug(
                    "NC-002: %s can reach datastore(s) %s without guardrail",
                    src, reached_ds,
                )

        affected = list(dict.fromkeys(affected))  # deduplicate, preserve order
        if not affected:
            return []
        return [_native_finding(check, affected)]

    # NC-003 ----------------------------------------------------------------

    def _check_nc003_model_deployment_no_auth(
        self,
        type_sets: dict[str, set[str]],
        adjacency: dict[str, set[str]],
        node_types_by_id: dict[str, str],
        nodes_by_id: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        check = NATIVE_CHECKS[2]  # ATLAS-NC-003
        affected: list[str] = []

        model_ids = type_sets.get("MODEL", set())
        deploy_ids = type_sets.get("DEPLOYMENT", set())
        auth_ids = type_sets.get("AUTH", set())

        if not model_ids or not deploy_ids:
            return []

        # If there are no AUTH nodes at all, flag all MODEL nodes
        if not auth_ids:
            for mid in model_ids:
                name = nodes_by_id.get(mid, {}).get("name", mid)
                affected.append(name)
                _log.debug("NC-003: model '%s' has no AUTH node in SBOM", name)
        else:
            # Check if any path from a MODEL reaches DEPLOYMENT without AUTH
            for mid in model_ids:
                visited: set[str] = {mid}
                queue = list(adjacency.get(mid, set()))
                reached_deploy = False
                passed_auth = False

                while queue:
                    nid = queue.pop()
                    if nid in visited:
                        continue
                    visited.add(nid)
                    ntype = node_types_by_id.get(nid, "")
                    if ntype == "AUTH":
                        passed_auth = True
                        break
                    if nid in deploy_ids:
                        reached_deploy = True
                    queue.extend(adjacency.get(nid, set()) - visited)

                if reached_deploy and not passed_auth:
                    name = nodes_by_id.get(mid, {}).get("name", mid)
                    affected.append(name)
                    _log.debug("NC-003: model '%s' reaches DEPLOYMENT without AUTH", name)

        affected = list(dict.fromkeys(affected))
        if not affected:
            return []
        return [_native_finding(check, affected)]

    # NC-004 ----------------------------------------------------------------

    def _check_nc004_outbound_agent_tool(
        self,
        nodes: list[dict[str, Any]],
        type_sets: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        check = NATIVE_CHECKS[3]  # ATLAS-NC-004
        affected: list[str] = []

        candidate_ids = type_sets.get("AGENT", set()) | type_sets.get("TOOL", set())

        for nid in candidate_ids:
            node = next((n for n in nodes if n.get("id") == nid), {})
            name = (node.get("name") or nid).lower()
            description = (node.get("description") or "").lower()
            combined = name + " " + description
            if any(kw in combined for kw in OUTBOUND_KEYWORDS):
                display = node.get("name", nid)
                affected.append(display)
                _log.debug("NC-004: outbound-capable node '%s'", display)

        if not affected:
            return []
        return [_native_finding(check, affected)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_atlas_block(
    technique_tuples: list[tuple[str, str]],
) -> dict[str, Any]:
    """Construct the ``atlas`` annotation block for a finding."""
    techniques: list[dict[str, Any]] = []
    for tid, confidence in technique_tuples:
        tech = TECHNIQUES.get(tid)
        if tech is None:
            _log.warning("unknown technique ID '%s' in VLA_TO_ATLAS mapping", tid)
            continue
        tactic_id = str(tech["tactic_id"])
        tactic = TACTICS.get(tactic_id, {})
        mitigation_list = [
            MITIGATIONS[mid]
            for mid in cast(list[str], tech.get("mitigation_ids") or [])
            if mid in MITIGATIONS
        ]
        techniques.append({
            "technique_id":   tid,
            "technique_name": tech["technique_name"],
            "tactic_id":      tactic_id,
            "tactic_name":    tactic.get("tactic_name", ""),
            "atlas_url":      tech["technique_url"],
            "confidence":     confidence,
            "basis":          "static",
            "mitigations":    mitigation_list,
        })
    return {"atlas_version": ATLAS_VERSION, "techniques": techniques}


def _native_finding(
    check: dict[str, object],
    affected: list[str],
) -> dict[str, Any]:
    """Build an annotated finding dict for a native ATLAS check."""
    technique_tuples: list[tuple[str, str]] = [
        (tid, conf)
        for tid, conf in cast(list[tuple[str, str]], check.get("techniques") or [])
    ]
    return {
        "rule_id":     check["check_id"],
        "severity":    _max_severity(technique_tuples),
        "title":       check["title"],
        "description": check["description"],
        "affected":    affected,
        "remediation": check["remediation"],
        "source":      "atlas-native",
        "atlas":       _build_atlas_block(technique_tuples),
    }


def _max_severity(technique_tuples: list[tuple[str, str]]) -> str:
    """Return the highest severity implied by the technique confidences."""
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    if not technique_tuples:
        return "LOW"
    best = min(technique_tuples, key=lambda t: order.get(t[1], 99))
    # Map confidence to a finding severity
    return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(best[1], "LOW")
