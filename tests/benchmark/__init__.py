"""
NuGuard Benchmark Suite for AI Discovery and Risk Assessment Accuracy

This package provides ground truth datasets and evaluation tools
for measuring the accuracy of:
1. Asset Discovery (Phase 1) - AI component detection
2. Risk Assessment (Phase 2) - Compliance gaps, covered controls, risk scoring

Usage:
    # Asset Discovery Benchmark
    python -m benchmark.evaluate --all
    python -m benchmark.evaluate --repo langchain-examples
    
    # Risk Assessment Benchmark
    python -m benchmark.evaluate_risk --all
    python -m benchmark.evaluate_risk --repo Healthcare-voice-agent
"""

# Asset Discovery schemas
from .schemas import (
    AssetType,
    GroundTruth,
    GroundTruthAsset,
    DiscoveredAsset,
    EvaluationResult,
    TypeMetrics,
    BenchmarkSuiteResult,
)

# Risk Assessment schemas
from .schemas_risk import (
    MatchFlexibility,
    Severity,
    GapType,
    EvidenceType,
    RedTeamAttackType,
    RiskBand,
    GroundTruthFinding,
    GroundTruthCoveredControl,
    ExpectedRiskScore,
    ExpectedRiskSummary,
    ExpectedRedTeamAttack,
    ExpectedRedTeamAttacks,
    RiskGroundTruth,
    FindingMatchResult,
    CoveredControlMatchResult,
    RiskTypeMetrics,
    RiskEvaluationResult,
    RiskBenchmarkSuiteResult,
)

__all__ = [
    # Asset Discovery
    "AssetType",
    "GroundTruth",
    "GroundTruthAsset",
    "DiscoveredAsset",
    "EvaluationResult",
    "TypeMetrics",
    "BenchmarkSuiteResult",
    # Risk Assessment
    "MatchFlexibility",
    "Severity",
    "GapType",
    "EvidenceType",
    "RedTeamAttackType",
    "RiskBand",
    "GroundTruthFinding",
    "GroundTruthCoveredControl",
    "ExpectedRiskScore",
    "ExpectedRiskSummary",
    "ExpectedRedTeamAttack",
    "ExpectedRedTeamAttacks",
    "RiskGroundTruth",
    "FindingMatchResult",
    "CoveredControlMatchResult",
    "RiskTypeMetrics",
    "RiskEvaluationResult",
    "RiskBenchmarkSuiteResult",
]
