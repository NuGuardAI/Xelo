"""Basic import and smoke tests for xelo toolbox evaluation utilities."""

from __future__ import annotations


def test_evaluate_importable() -> None:
    """Benchmark evaluation functions are importable."""
    from .evaluate import evaluate_discovery, list_available_benchmarks
    from .evaluate_risk import evaluate_risk_assessment, list_risk_benchmarks
    from .evaluate_policies import run_policy_benchmark

    assert callable(evaluate_discovery)
    assert callable(list_available_benchmarks)
    assert callable(evaluate_risk_assessment)
    assert callable(list_risk_benchmarks)
    assert callable(run_policy_benchmark)


def test_fetcher_importable() -> None:
    """Fetcher utilities are importable."""
    from .fetcher import fetch_repo_for_benchmark

    assert callable(fetch_repo_for_benchmark)


def test_policy_schemas_importable() -> None:
    """Policy schema classes are importable."""
    from .schemas import AssertionType, PolicyCategory, Severity

    assert AssertionType.MUST_EXIST.value == "must_exist"
    assert Severity.CRITICAL.value == "CRITICAL"
    assert PolicyCategory.REGULATORY.value == "regulatory"


def test_scan_result_schemas_importable() -> None:
    """Scan + risk result schemas are importable."""
    from .schemas import ScanEvaluationResult, PolicyEvaluationResult
    from .schemas_risk import RiskEvaluationResult

    assert ScanEvaluationResult is not None
    assert PolicyEvaluationResult is not None
    assert RiskEvaluationResult is not None
