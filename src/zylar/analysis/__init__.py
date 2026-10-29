"""Zylar analysis package providing deterministic detection, risk scoring, and threat correlation."""

from __future__ import annotations

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
    "DEFAULT_RISK_POLICY",
    "DetectionResult",
    "RULES_VERSION",
    "RiskPolicy",
    "RiskScoreResult",
    "RuleMatch",
    "evaluate_detection_rules",
    "evaluate_risk",
    "parse_valid_port",
]
