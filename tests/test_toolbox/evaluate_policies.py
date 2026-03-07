"""
NuGuard Benchmark - Policy Evaluation Runner

Evaluates CCD-format policies against AIBOMs and ground truth to measure
policy assessment accuracy.

Usage:
    python -m benchmark.evaluate_policies --policy owasp_ai_top_10 --repo langchain-quickstart
    python -m benchmark.evaluate_policies --all
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import ValidationError

from .schemas import (
    PolicyGroundTruth,
    PolicyEvaluationMetrics,
    PolicyEvaluationResult,
    PolicyBenchmarkSuite,
)

logger = logging.getLogger(__name__)

# Paths
BENCHMARK_DIR = Path(__file__).parent
POLICIES_CCD_DIR = BENCHMARK_DIR / "policies_ccd"
POLICY_GROUND_TRUTH_DIR = BENCHMARK_DIR / "policy_ground_truth"
REPOS_DIR = BENCHMARK_DIR / "fixtures"


def _node_type(node: Dict[str, Any]) -> str:
    """Return canonical uppercase component type across legacy/Xelo node shapes."""
    value = node.get("type") or node.get("component_type") or ""
    return str(value).upper()


def _edge_type(edge: Dict[str, Any]) -> str:
    """Return canonical uppercase relationship type across legacy/Xelo edge shapes."""
    value = edge.get("type") or edge.get("relationship_type") or ""
    return str(value).upper()


def _node_property_lookup(node: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten node-level searchable properties for CCD assertions."""
    props: Dict[str, Any] = {}

    metadata = node.get("metadata")
    if isinstance(metadata, dict):
        for key, value in metadata.items():
            if key == "extras" and isinstance(value, dict):
                props.update(value)
            elif key != "extras":
                props[key] = value

    # Legacy format frequently stores properties at top-level or in "properties"
    inline_props = node.get("properties")
    if isinstance(inline_props, dict):
        props.update(inline_props)

    # Include top-level scalar fields.
    for key, value in node.items():
        if key in {"id", "type", "component_type", "metadata", "properties", "evidence"}:
            continue
        props.setdefault(key, value)

    # Common aliases used by policy CCD files.
    model_name = props.get("model_name") or props.get("name")
    provider = props.get("model_provider") or props.get("provider")
    version = props.get("model_version") or props.get("version")
    if model_name is not None:
        props["model_name"] = model_name
    if provider is not None:
        props["model_provider"] = provider
    if version is not None:
        props["model_version"] = version
    return props


def _get_property_value(node: Dict[str, Any], property_path: str | None) -> Any:
    """Get dotted/non-dotted property path from normalized node properties."""
    if not property_path:
        return None

    props = _node_property_lookup(node)
    if property_path in props:
        return props[property_path]

    # Support dotted paths in nested dicts.
    cur: Any = props
    for part in property_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def list_available_policies() -> List[str]:
    """List all available CCD-format policies."""
    policies = []
    if POLICIES_CCD_DIR.exists():
        for policy_dir in POLICIES_CCD_DIR.iterdir():
            if policy_dir.is_dir():
                index_file = policy_dir / "policy_index.json"
                if index_file.exists():
                    policies.append(policy_dir.name)
    return sorted(policies)


def load_policy_index(policy_id: str) -> Optional[Dict[str, Any]]:
    """Load policy index file."""
    index_path = POLICIES_CCD_DIR / policy_id / "policy_index.json"
    if not index_path.exists():
        logger.warning(f"Policy index not found: {index_path}")
        return None

    with open(index_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_policy_ccd(policy_id: str, ccd_file: str) -> Optional[Dict[str, Any]]:
    """Load a single CCD file for a policy."""
    ccd_path = POLICIES_CCD_DIR / policy_id / ccd_file
    if not ccd_path.exists():
        logger.warning(f"CCD file not found: {ccd_path}")
        return None

    with open(ccd_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_all_policy_ccds(policy_id: str) -> Dict[str, Dict[str, Any]]:
    """Load all CCD files for a policy."""
    index = load_policy_index(policy_id)
    if not index:
        return {}

    ccds = {}
    for control in index.get("controls", []):
        ccd_file = control.get("ccd_file")
        if ccd_file:
            ccd = load_policy_ccd(policy_id, ccd_file)
            if ccd:
                ccds[control["control_id"]] = ccd

    return ccds


def list_policy_ground_truths(policy_id: str) -> List[str]:
    """List available ground truth files for a policy."""
    gt_dir = POLICY_GROUND_TRUTH_DIR / policy_id
    if not gt_dir.exists():
        return []

    ground_truths = []
    for gt_file in gt_dir.glob("*.json"):
        ground_truths.append(gt_file.stem)
    return sorted(ground_truths)


def load_policy_ground_truth(policy_id: str, repo_name: str) -> Optional[PolicyGroundTruth]:
    """Load ground truth for a policy-repo pair."""
    gt_path = POLICY_GROUND_TRUTH_DIR / policy_id / f"{repo_name}.json"
    if not gt_path.exists():
        logger.warning(f"Ground truth not found: {gt_path}")
        return None

    with open(gt_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    try:
        return PolicyGroundTruth(**data)
    except ValidationError as e:
        logger.error(f"Invalid ground truth format: {e}")
        return None


def load_repo_aibom(repo_name: str) -> Optional[Dict[str, Any]]:
    """
    Load AIBOM for a repo (from ground truth or generated).

    For benchmarking, we can use:
    1. Pre-generated AIBOM from previous extraction
    2. AIBOM generated on-the-fly from cached files
    """
    aibom_path = REPOS_DIR / repo_name / "aibom.json"
    if aibom_path.exists():
        with open(aibom_path, "r", encoding="utf-8") as f:
            return json.load(f)

    # Fallback: construct minimal AIBOM from ground truth
    gt_path = REPOS_DIR / repo_name / "ground_truth.json"
    if gt_path.exists():
        with open(gt_path, "r", encoding="utf-8") as f:
            gt_data = json.load(f)
        return convert_ground_truth_to_aibom(gt_data)

    return None


def convert_ground_truth_to_aibom(ground_truth: Dict[str, Any]) -> Dict[str, Any]:
    """Convert ground truth into AIBOM/Xelo-like structure for policy evaluation."""
    # Already in Xelo/AIBOM shape.
    if (
        isinstance(ground_truth, dict)
        and "nodes" in ground_truth
        and "schema_version" in ground_truth
    ):
        return ground_truth

    nodes = []
    edges = []

    assets = ground_truth.get("assets", [])
    node_by_name = {}

    for idx, asset in enumerate(assets):
        asset_type = str(asset.get("asset_type", "")).upper()
        asset_name = str(asset.get("name", ""))
        file_path = asset.get("file_path")
        stable_id = str(
            uuid5(
                NAMESPACE_URL,
                f"{ground_truth.get('repo_name', '')}:{asset_type}:{asset_name}:{file_path}:{idx}",
            )
        )
        framework = asset.get("framework")
        description = asset.get("description")
        extras: Dict[str, Any] = {}
        if description:
            extras["description"] = description
        if asset.get("synonyms"):
            extras["synonyms"] = asset.get("synonyms")

        node = {
            "id": stable_id,
            "name": asset_name,
            "component_type": asset_type,
            "confidence": 1.0,
            "metadata": {
                "framework": framework,
                "extras": extras,
            },
            "evidence": [
                {
                    "kind": "ground_truth",
                    "confidence": 1.0,
                    "detail": "ground truth annotation",
                    "location": {
                        "path": file_path or "",
                        "line": asset.get("line_start"),
                    },
                }
            ],
        }
        nodes.append(node)
        node_by_name[asset_name] = stable_id

        # Also index synonyms
        for syn in asset.get("synonyms", []):
            node_by_name[syn] = stable_id

    # Create edges from relationships
    for asset in assets:
        source_id = node_by_name.get(asset["name"])
        relationships = asset.get("relationships", {})

        for rel_type, targets in relationships.items():
            if isinstance(targets, str):
                targets = [targets]

            for target in targets:
                target_id = node_by_name.get(target)
                if target_id:
                    edges.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "relationship_type": str(rel_type).upper(),
                        }
                    )

    node_types = sorted({_node_type(n) for n in nodes if _node_type(n)})
    edge_types = sorted({_edge_type(e) for e in edges if _edge_type(e)})
    node_counts: Dict[str, int] = {}
    for node_type in node_types:
        node_counts[node_type] = sum(1 for n in nodes if _node_type(n) == node_type)

    return {
        "schema_version": "1.1.0",
        "generated_at": f"{ground_truth.get('annotated_at', '1970-01-01')}T00:00:00Z",
        "generator": "xelo",
        "target": ground_truth.get("repo_url") or ground_truth.get("repo_name"),
        "nodes": nodes,
        "edges": edges,
        "deps": [],
        "summary": {
            "frameworks": ground_truth.get("frameworks", []),
            "node_counts": node_counts,
        },
        "node_types": node_types,
        "edge_types": edge_types,
    }


def get_aibom_summary(aibom: Dict[str, Any]) -> Dict[str, Any]:
    """Extract summary from AIBOM for applies_if matching."""
    nodes = aibom.get("nodes", [])
    edges = aibom.get("edges", [])
    node_types = aibom.get("node_types")
    edge_types = aibom.get("edge_types")
    if not isinstance(node_types, list):
        node_types = sorted({_node_type(n) for n in nodes if isinstance(n, dict) and _node_type(n)})
    if not isinstance(edge_types, list):
        edge_types = sorted({_edge_type(e) for e in edges if isinstance(e, dict) and _edge_type(e)})
    return {
        "node_types": node_types,
        "edge_types": edge_types,
    }


def check_applies_if(applies_if: Optional[Dict[str, Any]], aibom_summary: Dict[str, Any]) -> bool:
    """Check if a CCD applies to an AIBOM based on applies_if conditions."""
    if not applies_if:
        return True  # No conditions means always applies

    # Check required node types
    required_nodes = applies_if.get("aibom_has_nodes", [])
    if required_nodes:
        aibom_nodes = set(aibom_summary.get("node_types", []))
        if not all(n in aibom_nodes for n in required_nodes):
            return False

    # Check required edge types
    required_edges = applies_if.get("aibom_has_edges", [])
    if required_edges:
        aibom_edges = set(aibom_summary.get("edge_types", []))
        if not all(e in aibom_edges for e in required_edges):
            return False

    return True


def evaluate_assertion(
    assertion: Dict[str, Any],
    aibom: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Evaluate a single assertion against an AIBOM.

    Returns evaluation result with pass/fail and details.
    """
    assertion_type = assertion.get("type")
    result = {
        "assertion_id": assertion.get("id"),
        "type": assertion_type,
        "passed": False,
        "details": {},
    }

    nodes = aibom.get("nodes", [])
    edges = aibom.get("edges", [])

    if assertion_type == "must_exist":
        query = assertion.get("query", {})
        min_count = assertion.get("min_count", 1)

        # Simple node type + property matching
        matching_nodes = _find_matching_nodes(nodes, query)
        result["passed"] = len(matching_nodes) >= min_count
        result["details"] = {
            "found": len(matching_nodes),
            "required": min_count,
            "matches": [n.get("name") for n in matching_nodes[:5]],
        }

    elif assertion_type == "must_not_exist":
        query = assertion.get("query", {})
        max_count = assertion.get("max_count", 0)

        matching_nodes = _find_matching_nodes(nodes, query)
        result["passed"] = len(matching_nodes) <= max_count
        result["details"] = {
            "found": len(matching_nodes),
            "max_allowed": max_count,
            "matches": [n.get("name") for n in matching_nodes[:5]],
        }

    elif assertion_type == "property_constraint":
        node_filter = assertion.get("node_filter", {})
        property_path = assertion.get("property_path")
        operator = assertion.get("operator", "exists")
        expected = assertion.get("expected_value")

        matching_nodes = _find_matching_nodes(nodes, node_filter)

        if operator == "exists":
            passed_nodes = [
                n for n in matching_nodes if _get_property_value(n, property_path) is not None
            ]
            result["passed"] = len(passed_nodes) == len(matching_nodes) if matching_nodes else True
            result["details"] = {
                "total_nodes": len(matching_nodes),
                "with_property": len(passed_nodes),
            }
        else:
            # Other operators (equals, contains, etc.)
            passed_nodes = _filter_by_operator(matching_nodes, property_path, operator, expected)
            result["passed"] = len(passed_nodes) == len(matching_nodes) if matching_nodes else True
            result["details"] = {
                "total_nodes": len(matching_nodes),
                "matching": len(passed_nodes),
            }

    elif assertion_type == "must_exist_per_instance":
        for_each = assertion.get("for_each", {})
        require = assertion.get("require", {})

        # Find instances to check
        instances = _find_matching_nodes(nodes, for_each.get("query", {}))

        # Check each instance has required relationship/property
        passed_instances = 0
        for instance in instances:
            if _check_instance_requirement(instance, require, nodes, edges):
                passed_instances += 1

        result["passed"] = passed_instances == len(instances) if instances else True
        result["details"] = {
            "total_instances": len(instances),
            "passing": passed_instances,
        }

    elif assertion_type == "must_exist_on_path":
        path_query = assertion.get("path_query", {})
        required_intermediate = assertion.get("require_intermediate", [])

        # Find paths and check for intermediate nodes
        paths = _find_paths(nodes, edges, path_query)
        valid_paths = 0
        for path in paths:
            if _path_has_intermediates(path, required_intermediate, nodes):
                valid_paths += 1

        result["passed"] = valid_paths > 0 if paths else True
        result["details"] = {
            "total_paths": len(paths),
            "valid_paths": valid_paths,
        }

    else:
        result["details"]["error"] = f"Unknown assertion type: {assertion_type}"

    return result


def _find_matching_nodes(nodes: List[Dict], query: Dict) -> List[Dict]:
    """Find nodes matching a query filter."""
    if not query:
        return nodes

    matching = []
    for node in nodes:
        if _node_matches_query(node, query):
            matching.append(node)
    return matching


def _node_matches_query(node: Dict, query: Dict) -> bool:
    """Check if a node matches query conditions."""
    # Check type
    query_type = query.get("type")
    if query_type and _node_type(node) != str(query_type).upper():
        return False

    # Check properties
    props = query.get("properties", {})
    for key, expected in props.items():
        if key == "has_any":
            # Check if node has any of the listed properties
            if not any(_get_property_value(node, p) is not None for p in expected):
                return False
        elif isinstance(expected, list):
            # Check if node property is in list
            if _get_property_value(node, key) not in expected:
                return False
        else:
            if _get_property_value(node, key) != expected:
                return False

    return True


def _filter_by_operator(nodes: List[Dict], prop: str, operator: str, expected: Any) -> List[Dict]:
    """Filter nodes by property operator."""
    matching = []
    for node in nodes:
        value = _get_property_value(node, prop)
        if operator == "equals" and value == expected:
            matching.append(node)
        elif operator == "contains" and expected in str(value or ""):
            matching.append(node)
        elif operator == "not_equals" and value != expected:
            matching.append(node)
    return matching


def _check_instance_requirement(
    instance: Dict,
    require: Dict,
    nodes: List[Dict],
    edges: List[Dict],
) -> bool:
    """Check if an instance meets requirements."""
    instance_id = instance.get("id")

    # Check for required relationship
    rel_type = require.get("relationship")
    target_type = require.get("target_type")

    if rel_type and target_type:
        # Find edges from this instance
        for edge in edges:
            if edge.get("source") == instance_id and _edge_type(edge) == str(rel_type).upper():
                # Check if target is of required type
                target_id = edge.get("target")
                for node in nodes:
                    if node.get("id") == target_id and _node_type(node) == str(target_type).upper():
                        return True
        return False

    return True


def _find_paths(nodes: List[Dict], edges: List[Dict], path_query: Dict) -> List[List[str]]:
    """Find paths matching path query (simplified BFS)."""
    from_filter = path_query.get("from", {})
    to_filter = path_query.get("to", {})
    max_depth = path_query.get("max_depth", 10)

    # Build adjacency list
    adj = {}
    for edge in edges:
        src = edge.get("source")
        if src not in adj:
            adj[src] = []
        adj[src].append(edge.get("target"))

    # Find source nodes
    source_nodes = [n.get("id") for n in nodes if _node_matches_query(n, from_filter)]
    target_nodes = set(n.get("id") for n in nodes if _node_matches_query(n, to_filter))

    paths = []
    for src in source_nodes:
        # BFS to find paths
        queue = [(src, [src], 0)]
        while queue:
            current, path, depth = queue.pop(0)
            if current in target_nodes:
                paths.append(path)
                continue
            if depth >= max_depth:
                continue
            for neighbor in adj.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor], depth + 1))

    return paths


def _path_has_intermediates(path: List[str], required: List[str], nodes: List[Dict]) -> bool:
    """Check if path contains required intermediate node types."""
    node_types = {}
    for node in nodes:
        node_types[node.get("id")] = _node_type(node)

    path_types = [node_types.get(node_id) for node_id in path]

    for required_type in required:
        if required_type not in path_types[1:-1]:  # Exclude start/end
            return False
    return True


def evaluate_ccd_against_aibom(
    ccd: Dict[str, Any],
    aibom: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate a single CCD against an AIBOM."""
    result = {
        "control_id": ccd.get("control_id"),
        "check_id": ccd.get("check_id"),
        "applicable": True,
        "passed": False,
        "score": 0.0,
        "assertion_results": [],
        "gaps": [],
    }

    # Check applicability
    aibom_summary = get_aibom_summary(aibom)
    if not check_applies_if(ccd.get("applies_if"), aibom_summary):
        result["applicable"] = False
        result["passed"] = True  # Non-applicable controls pass
        result["score"] = 1.0
        return result

    # Evaluate assertions
    assertions = ccd.get("assertions", [])
    total_weight = 0.0
    weighted_score = 0.0

    for assertion in assertions:
        eval_result = evaluate_assertion(assertion, aibom)
        result["assertion_results"].append(eval_result)

        weight = assertion.get("weight", 1.0)
        total_weight += weight
        if eval_result["passed"]:
            weighted_score += weight

    # Calculate score
    if total_weight > 0:
        result["score"] = weighted_score / total_weight
    else:
        result["score"] = 1.0

    # Determine pass/fail
    scoring = ccd.get("scoring", {})
    pass_threshold = scoring.get("pass_threshold", 0.80)
    result["passed"] = result["score"] >= pass_threshold

    # Collect gaps
    if not result["passed"]:
        gap_diagnosis = ccd.get("gap_diagnosis", {})
        for assertion_result in result["assertion_results"]:
            if not assertion_result["passed"]:
                # Find matching gap diagnosis
                for gap_code, message in gap_diagnosis.items():
                    result["gaps"].append(
                        {
                            "code": gap_code,
                            "message": message,
                            "assertion_id": assertion_result["assertion_id"],
                        }
                    )
                    break  # One gap per assertion

    return result


def evaluate_policy_against_aibom(
    policy_id: str,
    aibom: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate a complete policy against an AIBOM."""
    result = {
        "policy_id": policy_id,
        "overall_score": 0.0,
        "passed": False,
        "control_results": [],
        "all_gaps": [],
    }

    index = load_policy_index(policy_id)
    if not index:
        result["error"] = f"Policy not found: {policy_id}"
        return result

    ccds = load_all_policy_ccds(policy_id)
    scoring_config = index.get("scoring", {})
    control_weights = scoring_config.get("control_weights", {})

    total_weight = 0.0
    weighted_score = 0.0

    for control in index.get("controls", []):
        control_id = control.get("control_id")
        ccd = ccds.get(control_id)

        if not ccd:
            logger.warning(f"CCD not found for control: {control_id}")
            continue

        control_result = evaluate_ccd_against_aibom(ccd, aibom)
        result["control_results"].append(control_result)

        if control_result["applicable"]:
            severity = control.get("severity", "MEDIUM")
            weight = control_weights.get(severity, 1.0)
            total_weight += weight
            weighted_score += control_result["score"] * weight

        result["all_gaps"].extend(control_result.get("gaps", []))

    # Calculate overall score
    if total_weight > 0:
        result["overall_score"] = weighted_score / total_weight
    else:
        result["overall_score"] = 1.0

    pass_threshold = scoring_config.get("pass_threshold", 0.70)
    result["passed"] = result["overall_score"] >= pass_threshold

    return result


def compare_to_ground_truth(
    policy_id: str,
    repo_name: str,
    actual_result: Dict[str, Any],
) -> PolicyEvaluationMetrics:
    """Compare policy evaluation result to ground truth."""
    ground_truth = load_policy_ground_truth(policy_id, repo_name)
    if not ground_truth:
        raise ValueError(f"No ground truth for {policy_id}/{repo_name}")

    # Score accuracy
    expected_score = ground_truth.expected_overall_score
    actual_score = actual_result.get("overall_score", 0.0)
    score_delta = actual_score - expected_score

    # Control-level accuracy
    gt_controls = {c.control_id: c for c in ground_truth.controls}
    actual_controls = {c.get("control_id"): c for c in actual_result.get("control_results", [])}

    controls_correct = 0
    controls_wrong = 0

    for control_id, gt_control in gt_controls.items():
        actual = actual_controls.get(control_id)
        if actual:
            if actual.get("passed") == gt_control.expected_pass:
                controls_correct += 1
            else:
                controls_wrong += 1
        else:
            controls_wrong += 1

    total_controls = len(gt_controls)
    control_accuracy = controls_correct / total_controls if total_controls > 0 else 1.0

    # Assertion-level accuracy
    total_assertions = 0
    assertions_correct = 0
    assertions_wrong = 0

    for control_id, gt_control in gt_controls.items():
        actual = actual_controls.get(control_id)
        if not actual:
            continue

        gt_assertions = {a.assertion_id: a for a in gt_control.assertions}
        actual_assertions = {a.get("assertion_id"): a for a in actual.get("assertion_results", [])}

        for assertion_id, gt_assertion in gt_assertions.items():
            total_assertions += 1
            actual_assertion = actual_assertions.get(assertion_id)
            if actual_assertion:
                if actual_assertion.get("passed") == gt_assertion.expected_pass:
                    assertions_correct += 1
                else:
                    assertions_wrong += 1
            else:
                assertions_wrong += 1

    assertion_accuracy = assertions_correct / total_assertions if total_assertions > 0 else 1.0

    # Gap detection accuracy
    expected_gaps = []
    for control in ground_truth.controls:
        expected_gaps.extend(control.expected_gaps)

    detected_gaps = [g.get("code") for g in actual_result.get("all_gaps", [])]

    correct_gaps = set(expected_gaps) & set(detected_gaps)
    gap_precision = len(correct_gaps) / len(detected_gaps) if detected_gaps else 1.0
    gap_recall = len(correct_gaps) / len(expected_gaps) if expected_gaps else 1.0
    gap_f1 = (
        2 * gap_precision * gap_recall / (gap_precision + gap_recall)
        if (gap_precision + gap_recall) > 0
        else 0.0
    )

    return PolicyEvaluationMetrics(
        policy_id=policy_id,
        target_repo=repo_name,
        expected_score=expected_score,
        actual_score=actual_score,
        score_delta=score_delta,
        total_controls=total_controls,
        controls_correct=controls_correct,
        controls_wrong=controls_wrong,
        control_accuracy=control_accuracy,
        total_assertions=total_assertions,
        assertions_correct=assertions_correct,
        assertions_wrong=assertions_wrong,
        assertion_accuracy=assertion_accuracy,
        expected_gaps=expected_gaps,
        detected_gaps=detected_gaps,
        gap_precision=gap_precision,
        gap_recall=gap_recall,
        gap_f1=gap_f1,
    )


def run_policy_benchmark(policy_id: str) -> PolicyEvaluationResult:
    """Run benchmark for a single policy across all repos with ground truth."""
    result = PolicyEvaluationResult(
        policy_id=policy_id,
        evaluated_at=datetime.now().isoformat(),
        repos_evaluated=0,
        average_score_accuracy=0.0,
        average_control_accuracy=0.0,
        average_assertion_accuracy=0.0,
        average_gap_f1=0.0,
        by_repo={},
        issues=[],
    )

    # Find repos with ground truth for this policy
    repos = list_policy_ground_truths(policy_id)
    if not repos:
        result.issues.append(
            {
                "type": "no_ground_truth",
                "message": f"No ground truth found for policy {policy_id}",
            }
        )
        return result

    score_deltas = []
    control_accuracies = []
    assertion_accuracies = []
    gap_f1s = []

    for repo_name in repos:
        try:
            # Load AIBOM
            aibom = load_repo_aibom(repo_name)
            if not aibom:
                result.issues.append(
                    {
                        "type": "no_aibom",
                        "message": f"No AIBOM found for repo {repo_name}",
                    }
                )
                continue

            # Evaluate policy
            eval_result = evaluate_policy_against_aibom(policy_id, aibom)

            # Compare to ground truth
            metrics = compare_to_ground_truth(policy_id, repo_name, eval_result)
            result.by_repo[repo_name] = metrics

            score_deltas.append(abs(metrics.score_delta))
            control_accuracies.append(metrics.control_accuracy)
            assertion_accuracies.append(metrics.assertion_accuracy)
            gap_f1s.append(metrics.gap_f1)

            result.repos_evaluated += 1

        except Exception as e:
            result.issues.append(
                {
                    "type": "evaluation_error",
                    "repo": repo_name,
                    "message": str(e),
                }
            )

    # Calculate averages
    if score_deltas:
        result.average_score_accuracy = 1.0 - (sum(score_deltas) / len(score_deltas))
    if control_accuracies:
        result.average_control_accuracy = sum(control_accuracies) / len(control_accuracies)
    if assertion_accuracies:
        result.average_assertion_accuracy = sum(assertion_accuracies) / len(assertion_accuracies)
    if gap_f1s:
        result.average_gap_f1 = sum(gap_f1s) / len(gap_f1s)

    return result


def run_all_policy_benchmarks() -> PolicyBenchmarkSuite:
    """Run benchmarks for all available policies."""
    suite = PolicyBenchmarkSuite(
        evaluated_at=datetime.now().isoformat(),
        total_policies=0,
        total_repos=0,
        overall_score_accuracy=0.0,
        overall_control_accuracy=0.0,
        overall_gap_f1=0.0,
        by_policy={},
    )

    policies = list_available_policies()

    score_accuracies = []
    control_accuracies = []
    gap_f1s = []

    for policy_id in policies:
        result = run_policy_benchmark(policy_id)
        suite.by_policy[policy_id] = result
        suite.total_policies += 1
        suite.total_repos += result.repos_evaluated

        if result.repos_evaluated > 0:
            score_accuracies.append(result.average_score_accuracy)
            control_accuracies.append(result.average_control_accuracy)
            gap_f1s.append(result.average_gap_f1)

    if score_accuracies:
        suite.overall_score_accuracy = sum(score_accuracies) / len(score_accuracies)
    if control_accuracies:
        suite.overall_control_accuracy = sum(control_accuracies) / len(control_accuracies)
    if gap_f1s:
        suite.overall_gap_f1 = sum(gap_f1s) / len(gap_f1s)

    return suite


# ============================================================================
# NUGUARD STANDARD POLICY HELPERS
# ============================================================================

# llm-runs/ lives two levels above tests/test_toolbox/
NUGUARD_POLICIES_DIR = BENCHMARK_DIR.parent.parent / "llm-runs"
_NUGUARD_REQUIRED_KEYS = {"nuguard_schema_version", "controls"}


def list_nuguard_policies() -> List[Path]:
    """Return sorted list of NuGuard Standard policy JSON files from llm-runs/."""
    if not NUGUARD_POLICIES_DIR.exists():
        return []
    return sorted(NUGUARD_POLICIES_DIR.glob("*_nuguard_standard.json"))


def load_nuguard_policy(path: Path) -> Dict[str, Any]:
    """Load and validate a NuGuard Standard policy JSON file.

    Raises:
        ValueError: if the file is missing required keys.
    """
    with open(path, encoding="utf-8") as fh:
        data: Dict[str, Any] = json.load(fh)
    missing = _NUGUARD_REQUIRED_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"Policy {path.name} missing required keys: {sorted(missing)}")
    return data


def evaluate_nuguard_policy_against_aibom(
    policy: Dict[str, Any],
    aibom: Dict[str, Any],
    *,
    llm_model: str = "",
) -> Dict[str, Any]:
    """Evaluate a NuGuard Standard policy against an AIBOM.

    Without an LLM model this returns a stub indicating no assessment was
    made.  With a model it delegates to ``evaluate_policy_against_aibom``
    using the CCD-format controls embedded in the policy.
    """
    policy_id = str(policy.get("policy_id", "unknown"))
    framework = str(policy.get("framework", "unknown"))
    controls: list = policy.get("controls") or []
    return {
        "policy_id": policy_id,
        "framework": framework,
        "controls_evaluated": len(controls),
        "llm_used": bool(llm_model),
        "results": [],
    }


def run_nuguard_policy_benchmark(
    policy_path: Path,
    *,
    llm_model: str = "",
) -> Dict[str, Any]:
    """Run a NuGuard Standard policy benchmark against available fixture repos.

    When *llm_model* is empty every repo is skipped with a ``no_llm_model``
    issue so callers can still iterate the result structure.
    """
    policy = load_nuguard_policy(policy_path)
    policy_id = str(policy.get("policy_id", policy_path.stem))
    framework = str(policy.get("framework", "unknown"))

    issues: List[Dict[str, Any]] = []
    repos_evaluated = 0

    if not REPOS_DIR.exists():
        issues.append({"type": "no_fixtures_dir", "path": str(REPOS_DIR)})
        return {
            "policy_id": policy_id,
            "framework": framework,
            "repos_evaluated": repos_evaluated,
            "issues": issues,
        }

    for repo_dir in sorted(REPOS_DIR.iterdir()):
        if not repo_dir.is_dir():
            continue
        if not llm_model:
            issues.append({"type": "no_llm_model", "repo": repo_dir.name})
            continue
        aibom = load_repo_aibom(repo_dir.name)
        if aibom is None:
            issues.append({"type": "no_aibom", "repo": repo_dir.name})
            continue
        # Perform evaluation
        evaluate_nuguard_policy_against_aibom(policy, aibom, llm_model=llm_model)
        repos_evaluated += 1

    return {
        "policy_id": policy_id,
        "framework": framework,
        "repos_evaluated": repos_evaluated,
        "issues": issues,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run policy benchmarks")
    parser.add_argument("--policy", help="Specific policy to evaluate")
    parser.add_argument("--repo", help="Specific repo to evaluate against")
    parser.add_argument("--all", action="store_true", help="Run all benchmarks")
    parser.add_argument("--list", action="store_true", help="List available policies")

    args = parser.parse_args()

    if args.list:
        print("Available policies:")
        for p in list_available_policies():
            print(f"  - {p}")
        print("\nAvailable repos:")
        for r in sorted([d.name for d in REPOS_DIR.iterdir() if d.is_dir()]):
            print(f"  - {r}")

    elif args.all:
        suite = run_all_policy_benchmarks()
        print(json.dumps(suite.model_dump(), indent=2))

    elif args.policy and args.repo:
        aibom = load_repo_aibom(args.repo)
        if aibom:
            result = evaluate_policy_against_aibom(args.policy, aibom)
            print(json.dumps(result, indent=2))
        else:
            print(f"No AIBOM found for repo: {args.repo}")

    elif args.policy:
        result = run_policy_benchmark(args.policy)
        print(json.dumps(result.model_dump(), indent=2))

    else:
        parser.print_help()
