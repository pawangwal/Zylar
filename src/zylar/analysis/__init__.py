"""Zylar analysis package providing deterministic detection, risk scoring, and threat correlation."""

from __future__ import annotations

from zylar.analysis.correlation_service import (
    CorrelationGraphResult,
    build_correlation_graph,
)
from zylar.analysis.detection_rules import (
    RULES_VERSION,
    DetectionResult,
    RuleMatch,
    evaluate_detection_rules,
)
from zylar.analysis.risk_scoring import (
    DEFAULT_RISK_POLICY,
    RiskPolicy,
    RiskScoreResult,
    evaluate_risk,
    parse_valid_port,
)

__all__ = [
    "CorrelationGraphResult",
    "DEFAULT_RISK_POLICY",
    "DetectionResult",
    "RULES_VERSION",
    "RiskPolicy",
    "RiskScoreResult",
    "RuleMatch",
    "build_correlation_graph",
    "evaluate_detection_rules",
    "evaluate_risk",
    "parse_valid_port",
]
