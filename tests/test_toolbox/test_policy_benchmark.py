"""
Tests for the Policy Benchmark Evaluation Framework

Tests CCD-format policy loading, AIBOM evaluation, and ground truth comparison.
"""

import pytest
from datetime import date


# ============================================================================
# SCHEMA TESTS
# ============================================================================

class TestPolicyBenchmarkSchemas:
    """Test policy benchmark Pydantic schemas."""
    
    def test_assertion_type_enum(self):
        """Test AssertionType enum values."""
        from .schemas import AssertionType
        
        assert AssertionType.MUST_EXIST.value == "must_exist"
        assert AssertionType.MUST_NOT_EXIST.value == "must_not_exist"
        assert AssertionType.MUST_EXIST_PER_INSTANCE.value == "must_exist_per_instance"
        assert AssertionType.MUST_EXIST_ON_PATH.value == "must_exist_on_path"
        assert AssertionType.COUNT_THRESHOLD.value == "count_threshold"
        assert AssertionType.PROPERTY_CONSTRAINT.value == "property_constraint"
    
    def test_severity_enum(self):
        """Test Severity enum values."""
        from .schemas import Severity
        
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
    
    def test_policy_category_enum(self):
        """Test PolicyCategory enum values."""
        from .schemas import PolicyCategory
        
        assert PolicyCategory.REGULATORY.value == "regulatory"
        assert PolicyCategory.SECURITY.value == "security"
    
    def test_expected_assertion_model(self):
        """Test ExpectedAssertion Pydantic model."""
        from .schemas import ExpectedAssertion, AssertionType, Severity
        
        assertion = ExpectedAssertion(
            assertion_id="test_assertion",
            type=AssertionType.MUST_EXIST,
            expected_pass=True,
            severity=Severity.HIGH,
            description="Test assertion",
            weight=1.5,
        )
        
        assert assertion.assertion_id == "test_assertion"
        assert assertion.type == AssertionType.MUST_EXIST
        assert assertion.expected_pass is True
        assert assertion.weight == 1.5
    
    def test_control_ground_truth_model(self):
        """Test ControlGroundTruth Pydantic model."""
        from .schemas import ControlGroundTruth, ExpectedAssertion, AssertionType, Severity
        
        control = ControlGroundTruth(
            control_id="OWASP-A01",
            title="Prompt Injection",
            expected_applicable=True,
            expected_pass=False,
            expected_score=0.3,
            assertions=[
                ExpectedAssertion(
                    assertion_id="has_guardrails",
                    type=AssertionType.MUST_EXIST,
                    expected_pass=False,
                    severity=Severity.HIGH,
                    description="Should have guardrails",
                )
            ],
            expected_gaps=["no_guardrails"],
        )
        
        assert control.control_id == "OWASP-A01"
        assert control.expected_pass is False
        assert len(control.assertions) == 1
        assert "no_guardrails" in control.expected_gaps
    
    def test_policy_ground_truth_model(self):
        """Test PolicyGroundTruth Pydantic model."""
        from .schemas import (
            PolicyGroundTruth, ControlGroundTruth, PolicyCategory
        )
        
        policy_gt = PolicyGroundTruth(
            policy_id="owasp_ai_top_10",
            policy_name="OWASP AI Top 10",
            category=PolicyCategory.SECURITY,
            target_repo="test-repo",
            expected_overall_score=0.5,
            controls=[
                ControlGroundTruth(
                    control_id="A01",
                    title="Test Control",
                    expected_applicable=True,
                    expected_pass=True,
                )
            ],
            annotated_at=date(2026, 2, 7),
        )
        
        assert policy_gt.policy_id == "owasp_ai_top_10"
        assert policy_gt.expected_overall_score == 0.5
        assert len(policy_gt.controls) == 1
    
    def test_policy_ground_truth_pass_rate(self):
        """Test expected_control_pass_rate calculation."""
        from .schemas import PolicyGroundTruth, ControlGroundTruth, PolicyCategory
        
        policy_gt = PolicyGroundTruth(
            policy_id="test",
            policy_name="Test Policy",
            category=PolicyCategory.SECURITY,
            target_repo="test-repo",
            expected_overall_score=0.5,
            controls=[
                ControlGroundTruth(control_id="A", title="A", expected_applicable=True, expected_pass=True),
                ControlGroundTruth(control_id="B", title="B", expected_applicable=True, expected_pass=False),
                ControlGroundTruth(control_id="C", title="C", expected_applicable=False, expected_pass=True),
            ],
            annotated_at=date(2026, 2, 7),
        )
        
        # Only 2 applicable controls: A (pass), B (fail) = 50%
        assert policy_gt.expected_control_pass_rate() == 0.5
    
    def test_policy_evaluation_metrics_model(self):
        """Test PolicyEvaluationMetrics model."""
        from .schemas import PolicyEvaluationMetrics
        
        metrics = PolicyEvaluationMetrics(
            policy_id="owasp",
            target_repo="test",
            expected_score=0.8,
            actual_score=0.75,
            score_delta=-0.05,
            total_controls=10,
            controls_correct=8,
            controls_wrong=2,
            control_accuracy=0.8,
            total_assertions=20,
            assertions_correct=18,
            assertions_wrong=2,
            assertion_accuracy=0.9,
            expected_gaps=["gap1", "gap2"],
            detected_gaps=["gap1", "gap3"],
            gap_precision=0.5,
            gap_recall=0.5,
            gap_f1=0.5,
        )
        
        assert metrics.score_delta == -0.05
        assert metrics.control_accuracy == 0.8
        assert metrics.assertion_accuracy == 0.9


# ============================================================================
# EVALUATION FUNCTION TESTS
# ============================================================================

class TestPolicyEvaluation:
    """Test policy evaluation functions."""
    
    @pytest.fixture
    def sample_aibom(self):
        """Sample AIBOM for testing."""
        return {
            "schema_version": "1.1.0",
            "generated_at": "2026-03-01T00:00:00Z",
            "generator": "xelo",
            "target": "https://github.com/example/test-repo",
            "nodes": [
                {
                    "id": "agent_1",
                    "name": "TestAgent",
                    "component_type": "AGENT",
                    "confidence": 0.95,
                    "metadata": {
                        "extras": {"file_path": "main.py"},
                    },
                    "evidence": [],
                },
                {
                    "id": "model_1",
                    "name": "GPT4",
                    "component_type": "MODEL",
                    "confidence": 0.92,
                    "metadata": {
                        "model_name": "gpt-4",
                        "extras": {"provider": "openai"},
                    },
                    "evidence": [],
                },
                {
                    "id": "tool_1",
                    "name": "search_tool",
                    "component_type": "TOOL",
                    "confidence": 0.90,
                    "metadata": {"extras": {}},
                    "evidence": [],
                },
                {
                    "id": "guardrail_1",
                    "name": "input_filter",
                    "component_type": "GUARDRAIL",
                    "confidence": 0.88,
                    "metadata": {"extras": {"guardrail_type": "input_validation"}},
                    "evidence": [],
                },
            ],
            "edges": [
                {"source": "agent_1", "target": "model_1", "relationship_type": "USES"},
                {"source": "agent_1", "target": "tool_1", "relationship_type": "USES"},
                {"source": "agent_1", "target": "guardrail_1", "relationship_type": "PROTECTS"},
            ],
            "deps": [],
            "node_types": ["AGENT", "MODEL", "TOOL", "GUARDRAIL"],
            "edge_types": ["USES", "PROTECTS"],
        }
    
    @pytest.fixture
    def sample_aibom_no_guardrails(self):
        """Sample AIBOM without guardrails."""
        return {
            "schema_version": "1.1.0",
            "generated_at": "2026-03-01T00:00:00Z",
            "generator": "xelo",
            "target": "https://github.com/example/test-repo-insecure",
            "nodes": [
                {"id": "agent_1", "name": "TestAgent", "component_type": "AGENT", "confidence": 0.9, "metadata": {"extras": {}}, "evidence": []},
                {"id": "model_1", "name": "GPT4", "component_type": "MODEL", "confidence": 0.9, "metadata": {"extras": {}}, "evidence": []},
            ],
            "edges": [
                {"source": "agent_1", "target": "model_1", "relationship_type": "USES"},
            ],
            "deps": [],
            "node_types": ["AGENT", "MODEL"],
            "edge_types": ["USES"],
        }
    
    def test_get_aibom_summary(self, sample_aibom):
        """Test AIBOM summary extraction."""
        from .evaluate_policies import get_aibom_summary
        
        summary = get_aibom_summary(sample_aibom)
        
        assert "AGENT" in summary["node_types"]
        assert "GUARDRAIL" in summary["node_types"]
        assert "USES" in summary["edge_types"]
    
    def test_check_applies_if_no_conditions(self, sample_aibom):
        """Test applies_if with no conditions (always applies)."""
        from .evaluate_policies import check_applies_if, get_aibom_summary
        
        result = check_applies_if(None, get_aibom_summary(sample_aibom))
        assert result is True
        
        result = check_applies_if({}, get_aibom_summary(sample_aibom))
        assert result is True
    
    def test_check_applies_if_node_types(self, sample_aibom, sample_aibom_no_guardrails):
        """Test applies_if with node type conditions."""
        from .evaluate_policies import check_applies_if, get_aibom_summary
        
        applies_if = {"aibom_has_nodes": ["AGENT", "GUARDRAIL"]}
        
        # Sample AIBOM has GUARDRAIL
        result = check_applies_if(applies_if, get_aibom_summary(sample_aibom))
        assert result is True
        
        # Sample AIBOM without guardrails doesn't have GUARDRAIL
        result = check_applies_if(applies_if, get_aibom_summary(sample_aibom_no_guardrails))
        assert result is False
    
    def test_check_applies_if_edge_types(self, sample_aibom):
        """Test applies_if with edge type conditions."""
        from .evaluate_policies import check_applies_if, get_aibom_summary
        
        applies_if = {"aibom_has_edges": ["USES", "PROTECTS"]}
        result = check_applies_if(applies_if, get_aibom_summary(sample_aibom))
        assert result is True
        
        applies_if = {"aibom_has_edges": ["nonexistent_edge"]}
        result = check_applies_if(applies_if, get_aibom_summary(sample_aibom))
        assert result is False
    
    def test_evaluate_assertion_must_exist(self, sample_aibom):
        """Test must_exist assertion evaluation."""
        from .evaluate_policies import evaluate_assertion
        
        # Should find GUARDRAIL
        assertion = {
            "id": "guardrail_exists",
            "type": "must_exist",
            "query": {"type": "GUARDRAIL"},
            "min_count": 1,
        }
        result = evaluate_assertion(assertion, sample_aibom)
        assert result["passed"] is True
        assert result["details"]["found"] >= 1
    
    def test_evaluate_assertion_must_not_exist(self, sample_aibom):
        """Test must_not_exist assertion evaluation."""
        from .evaluate_policies import evaluate_assertion
        
        # Should not find deprecated models
        assertion = {
            "id": "no_deprecated",
            "type": "must_not_exist",
            "query": {"type": "MODEL", "properties": {"model_name": ["gpt-3"]}},
            "max_count": 0,
        }
        result = evaluate_assertion(assertion, sample_aibom)
        assert result["passed"] is True
    
    def test_evaluate_assertion_property_constraint(self, sample_aibom):
        """Test property_constraint assertion evaluation."""
        from .evaluate_policies import evaluate_assertion
        
        # Check MODEL has provider
        assertion = {
            "id": "has_provider",
            "type": "property_constraint",
            "node_filter": {"type": "MODEL"},
            "property_path": "model_provider",
            "operator": "exists",
            "expected_value": True,
        }
        result = evaluate_assertion(assertion, sample_aibom)
        assert result["passed"] is True
    
    def test_evaluate_ccd_against_aibom(self, sample_aibom):
        """Test CCD evaluation against AIBOM."""
        from .evaluate_policies import evaluate_ccd_against_aibom
        
        ccd = {
            "control_id": "TEST-01",
            "check_id": "test-guardrails",
            "applies_if": {"aibom_has_nodes": ["AGENT"]},
            "assertions": [
                {
                    "id": "has_guardrail",
                    "type": "must_exist",
                    "query": {"type": "GUARDRAIL"},
                    "min_count": 1,
                    "weight": 1.0,
                }
            ],
            "scoring": {"pass_threshold": 0.80},
        }
        
        result = evaluate_ccd_against_aibom(ccd, sample_aibom)
        
        assert result["control_id"] == "TEST-01"
        assert result["applicable"] is True
        assert result["passed"] is True
        assert result["score"] == 1.0
    
    def test_evaluate_ccd_not_applicable(self, sample_aibom_no_guardrails):
        """Test CCD evaluation when control doesn't apply."""
        from .evaluate_policies import evaluate_ccd_against_aibom
        
        ccd = {
            "control_id": "TEST-02",
            "applies_if": {"aibom_has_nodes": ["DATASTORE"]},  # No DATASTORE in AIBOM
            "assertions": [
                {"id": "test", "type": "must_exist", "query": {"type": "GUARDRAIL"}}
            ],
            "scoring": {},
        }
        
        result = evaluate_ccd_against_aibom(ccd, sample_aibom_no_guardrails)
        
        assert result["applicable"] is False
        assert result["passed"] is True  # Non-applicable controls pass
        assert result["score"] == 1.0


# ============================================================================
# AIBOM CONVERSION TESTS
# ============================================================================

class TestAIBOMConversion:
    """Test AIBOM conversion from ground truth."""
    
    def test_convert_ground_truth_to_aibom(self):
        """Test converting asset ground truth to AIBOM structure."""
        from .evaluate_policies import convert_ground_truth_to_aibom
        
        ground_truth = {
            "repo_name": "test-repo",
            "assets": [
                {
                    "asset_type": "AGENT",
                    "name": "TestAgent",
                    "file_path": "main.py",
                    "line_start": 10,
                    "relationships": {"uses_model": "GPT4"},
                },
                {
                    "asset_type": "MODEL",
                    "name": "GPT4",
                    "file_path": "config.py",
                    "line_start": 5,
                },
            ],
        }
        
        aibom = convert_ground_truth_to_aibom(ground_truth)
        
        assert aibom["schema_version"] == "1.1.0"
        assert aibom["generator"] == "xelo"
        assert aibom["target"] == "test-repo"
        assert len(aibom["nodes"]) == 2
        assert len(aibom["edges"]) == 1
        assert "AGENT" in aibom["node_types"]
        assert "MODEL" in aibom["node_types"]
        assert "USES_MODEL" in aibom["edge_types"]


# ============================================================================
# POLICY LOADING TESTS
# ============================================================================

class TestPolicyLoading:
    """Test policy file loading functions."""
    
    def test_list_available_policies(self):
        """Test listing available CCD-format policies."""
        from .evaluate_policies import list_available_policies
        
        policies = list_available_policies()
        
        # Should find owasp_ai_top_10
        assert "owasp_ai_top_10" in policies
    
    def test_load_policy_index(self):
        """Test loading policy index file."""
        from .evaluate_policies import load_policy_index
        
        index = load_policy_index("owasp_ai_top_10")
        
        assert index is not None
        assert index["policy_id"] == "owasp_ai_top_10"
        assert "controls" in index
    
    def test_load_policy_ccd(self):
        """Test loading individual CCD file."""
        from .evaluate_policies import load_policy_ccd
        
        ccd = load_policy_ccd("owasp_ai_top_10", "A01_prompt_injection.json")
        
        assert ccd is not None
        assert ccd["control_id"] == "OWASP-A01"
        assert "assertions" in ccd
    
    def test_load_all_policy_ccds(self):
        """Test loading all CCDs for a policy."""
        from .evaluate_policies import load_all_policy_ccds
        
        ccds = load_all_policy_ccds("owasp_ai_top_10")
        
        # Should have loaded at least the ones we created
        assert "OWASP-A01" in ccds
        assert "OWASP-A02" in ccds
        assert "OWASP-A05" in ccds
    
    def test_list_policy_ground_truths(self):
        """Test listing ground truth files for a policy."""
        from .evaluate_policies import list_policy_ground_truths
        
        ground_truths = list_policy_ground_truths("owasp_ai_top_10")
        
        # Should find langchain-quickstart
        assert "langchain-quickstart" in ground_truths
    
    def test_load_policy_ground_truth(self):
        """Test loading policy ground truth."""
        from .evaluate_policies import load_policy_ground_truth
        
        gt = load_policy_ground_truth("owasp_ai_top_10", "langchain-quickstart")
        
        assert gt is not None
        assert gt.policy_id == "owasp_ai_top_10"
        assert gt.target_repo == "langchain-quickstart"
        assert len(gt.controls) > 0


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestPolicyBenchmarkIntegration:
    """Integration tests for full policy benchmark workflow."""
    
    def test_evaluate_policy_against_converted_aibom(self):
        """Test evaluating a policy against AIBOM converted from ground truth."""
        from .evaluate_policies import (
            evaluate_policy_against_aibom,
            load_repo_aibom,
        )
        
        # Load AIBOM (will convert from ground truth)
        aibom = load_repo_aibom("langchain-quickstart")
        
        if aibom:  # Only run if we have an AIBOM
            result = evaluate_policy_against_aibom("owasp_ai_top_10", aibom)
            
            assert result["policy_id"] == "owasp_ai_top_10"
            assert "overall_score" in result
            assert "control_results" in result
            assert len(result["control_results"]) > 0
    
    def test_full_benchmark_run(self):
        """Test running full policy benchmark."""
        from .evaluate_policies import run_policy_benchmark
        
        result = run_policy_benchmark("owasp_ai_top_10")
        
        assert result.policy_id == "owasp_ai_top_10"
        assert result.evaluated_at is not None
        # May have issues if ground truth repos don't exist
        if result.repos_evaluated > 0:
            assert result.average_control_accuracy >= 0
            assert result.average_control_accuracy <= 1


# ============================================================================
# PATH FINDING TESTS
# ============================================================================

class TestPathFinding:
    """Test path finding for must_exist_on_path assertions."""
    
    def test_find_paths_simple(self):
        """Test finding paths in simple graph."""
        from .evaluate_policies import _find_paths
        
        nodes = [
            {"id": "agent_1", "component_type": "AGENT"},
            {"id": "guardrail_1", "component_type": "GUARDRAIL"},
            {"id": "tool_1", "component_type": "TOOL"},
        ]
        edges = [
            {"source": "agent_1", "target": "guardrail_1", "relationship_type": "PROTECTS"},
            {"source": "guardrail_1", "target": "tool_1", "relationship_type": "USES"},
        ]
        
        path_query = {
            "from": {"type": "AGENT"},
            "to": {"type": "TOOL"},
            "max_depth": 5,
        }
        
        paths = _find_paths(nodes, edges, path_query)
        
        assert len(paths) == 1
        assert paths[0] == ["agent_1", "guardrail_1", "tool_1"]
    
    def test_path_has_intermediates(self):
        """Test checking for intermediate nodes on path."""
        from .evaluate_policies import _path_has_intermediates
        
        nodes = [
            {"id": "agent_1", "component_type": "AGENT"},
            {"id": "guardrail_1", "component_type": "GUARDRAIL"},
            {"id": "tool_1", "component_type": "TOOL"},
        ]
        
        path = ["agent_1", "guardrail_1", "tool_1"]
        
        # Should find GUARDRAIL as intermediate
        assert _path_has_intermediates(path, ["GUARDRAIL"], nodes) is True
        
        # Should not find MODEL as intermediate
        assert _path_has_intermediates(path, ["MODEL"], nodes) is False


# ============================================================================
# NUGUARD STANDARD POLICY TESTS
# ============================================================================

class TestNuguardPolicies:
    """Tests for NuGuard Standard policy helpers (llm-runs/*.json)."""

    def test_list_nuguard_policies_returns_three(self):
        """``list_nuguard_policies`` should find the three bundled policy files."""
        from .evaluate_policies import list_nuguard_policies

        policies = list_nuguard_policies()
        assert len(policies) == 3, (
            f"Expected 3 NuGuard Standard policy files, got {len(policies)}: {policies}"
        )

    def test_list_nuguard_policies_are_paths(self):
        """Each entry should be a Path pointing to an existing file."""
        from pathlib import Path
        from .evaluate_policies import list_nuguard_policies

        for p in list_nuguard_policies():
            assert isinstance(p, Path)
            assert p.exists(), f"Policy file does not exist: {p}"
            assert p.suffix == ".json"

    def test_nuguard_policy_owasp_structure(self):
        """OWASP AI Top 10 NuGuard Standard policy should have required fields."""
        from .evaluate_policies import list_nuguard_policies, load_nuguard_policy

        owasp_policies = [
            p for p in list_nuguard_policies() if "owasp" in p.stem.lower()
        ]
        assert owasp_policies, "owasp*_nuguard_standard.json not found in llm-runs/"
        policy = load_nuguard_policy(owasp_policies[0])

        assert "nuguard_schema_version" in policy
        assert "policy_id" in policy
        assert "framework" in policy
        assert "controls" in policy
        assert isinstance(policy["controls"], list)
        assert len(policy["controls"]) > 0

    def test_nuguard_policy_nist_structure(self):
        """NIST AI RMF NuGuard Standard policy should have required fields."""
        from .evaluate_policies import list_nuguard_policies, load_nuguard_policy

        nist_policies = [
            p for p in list_nuguard_policies() if "nist" in p.stem.lower()
        ]
        assert nist_policies, "nist*_nuguard_standard.json not found in llm-runs/"
        policy = load_nuguard_policy(nist_policies[0])

        assert "nuguard_schema_version" in policy
        assert "controls" in policy
        for ctrl in policy["controls"]:
            assert "control_id" in ctrl
            # NIST controls use category instead of severity
            assert "category" in ctrl or "severity" in ctrl

    def test_nuguard_policy_soc2_structure(self):
        """SOC2 NuGuard Standard policy should have required fields."""
        from .evaluate_policies import list_nuguard_policies, load_nuguard_policy

        soc2_policies = [
            p for p in list_nuguard_policies() if "soc2" in p.stem.lower()
        ]
        assert soc2_policies, "soc2*_nuguard_standard.json not found in llm-runs/"
        policy = load_nuguard_policy(soc2_policies[0])

        assert "nuguard_schema_version" in policy
        assert "controls" in policy

    def test_load_nuguard_policy_invalid_raises(self, tmp_path):
        """``load_nuguard_policy`` raises ValueError for invalid JSON structure."""
        from .evaluate_policies import load_nuguard_policy

        bad_file = tmp_path / "bad_policy.json"
        bad_file.write_text('{"foo": "bar"}', encoding="utf-8")

        with pytest.raises(ValueError, match="missing required keys"):
            load_nuguard_policy(bad_file)

    def test_evaluate_nuguard_policy_importable(self):
        """``evaluate_nuguard_policy_against_aibom`` must be importable."""
        from .evaluate_policies import evaluate_nuguard_policy_against_aibom  # noqa: F401

        assert callable(evaluate_nuguard_policy_against_aibom)

    def test_run_nuguard_policy_benchmark_importable(self):
        """``run_nuguard_policy_benchmark`` must be importable."""
        from .evaluate_policies import run_nuguard_policy_benchmark  # noqa: F401

        assert callable(run_nuguard_policy_benchmark)

    def test_run_nuguard_policy_benchmark_no_llm_records_issue(self):
        """When ``llm_model`` is empty, repos are skipped with a recorded issue."""
        from .evaluate_policies import list_nuguard_policies, run_nuguard_policy_benchmark

        policies = list_nuguard_policies()
        if not policies:
            pytest.skip("No NuGuard Standard policy files found")

        # Run without an LLM model — should enumerate repos but skip assessment
        result = run_nuguard_policy_benchmark(policies[0], llm_model="")

        assert "policy_id" in result
        assert "framework" in result
        assert result["repos_evaluated"] == 0
        # All repos should have a "no_llm_model" issue
        for issue in result["issues"]:
            assert issue["type"] in ("no_llm_model", "no_fixtures_dir", "no_aibom")


# ============================================================================
# BENCHMARK PLUGIN TESTS
# ============================================================================

class TestBenchmarkPlugins:
    """Tests for run_bench_plugins and the evaluate.py plugin integration."""

    def test_run_bench_plugins_importable(self):
        """``run_bench_plugins`` must be importable from evaluate."""
        from .evaluate import run_bench_plugins  # noqa: F401

        assert callable(run_bench_plugins)

    def test_run_bench_plugins_markdown_only(self, tmp_path):
        """Markdown plugin runs without LLM when no policy_files are given."""
        from .evaluate import run_bench_plugins

        minimal_sbom: dict = {
            "schema_version": "1.1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "generator": "xelo",
            "target": "pytest-test",
            "nodes": [],
            "edges": [],
            "deps": [],
            "summary": {"frameworks": [], "node_counts": {}},
        }
        report = run_bench_plugins(minimal_sbom, "test-repo", tmp_path, policy_files=[])

        assert report["markdown_saved"] is True
        md_path = tmp_path / "test-repo" / "report.md"
        assert md_path.exists()
        assert md_path.read_text(encoding="utf-8").strip() != ""

    def test_run_bench_plugins_no_policy_without_llm(self, tmp_path):
        """Policy step is skipped and an issue is recorded when llm_model is empty."""
        from .evaluate import run_bench_plugins
        from pathlib import Path

        minimal_sbom: dict = {
            "schema_version": "1.1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "generator": "xelo",
            "target": "pytest-test",
            "nodes": [],
            "edges": [],
            "deps": [],
            "summary": {"frameworks": [], "node_counts": {}},
        }
        # Pass a non-empty policy_files list but no llm_model
        dummy_policy = Path("/nonexistent/policy.json")
        report = run_bench_plugins(
            minimal_sbom,
            "test-repo",
            tmp_path,
            policy_files=[dummy_policy],
            plugin_llm_model="",
        )

        # Markdown still succeeds
        assert report["markdown_saved"] is True
        # No policy results because llm_model is absent
        assert report["policy_results"] == {}
        # An issue is recorded
        issue_types = [i["type"] for i in report["issues"]]
        assert "no_llm_model" in issue_types

    def test_nuguard_policies_dir_constant(self):
        """NUGUARD_POLICIES_DIR in evaluate.py should point to llm-runs/."""
        from .evaluate import NUGUARD_POLICIES_DIR
        from pathlib import Path

        assert isinstance(NUGUARD_POLICIES_DIR, Path)
        assert NUGUARD_POLICIES_DIR.name == "llm-runs"
        assert NUGUARD_POLICIES_DIR.exists(), (
            f"NUGUARD_POLICIES_DIR does not exist: {NUGUARD_POLICIES_DIR}"
        )
