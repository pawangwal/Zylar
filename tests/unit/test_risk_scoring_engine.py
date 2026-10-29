from __future__ import annotations

import pytest
from pydantic import ValidationError

from zylar.analysis.risk_scoring import (
    DEFAULT_RISK_POLICY,
    RiskPolicy,
    RiskScoreResult,
    evaluate_risk,
)


def test_evaluate_risk_zero_for_empty_anomalies():
    result = evaluate_risk({"anomalies": [], "attack_classification": "Brute Force"})
    assert isinstance(result, RiskScoreResult)
    assert result.risk_score == 0
    assert result.risk_category == "Low"
    assert result.policy_version == "risk-policy-v1"
    assert result.raw_factors["volume"] == 0.0
    assert result.weighted_contributions["volume"] == 0.0


def test_evaluate_risk_zero_for_none_classification():
    result = evaluate_risk(
        {
            "anomalies": [{"source_ip": "10.0.0.1", "destination_port": 22}],
            "attack_classification": "None",
        }
    )
    assert result.risk_score == 0
    assert result.risk_category == "Low"


def test_evaluate_risk_deterministic_reproducibility():
    payload = {
        "attack_classification": "Brute Force",
        "anomalies": [
            {"source_ip": "192.168.1.100", "user": "root", "destination_port": 22}
            for _ in range(10)
        ],
        "historical_recurrence": 40,
        "graph_centrality": 25.0,
    }
    r1 = evaluate_risk(payload)
    r2 = evaluate_risk(payload)
    assert r1.risk_score == r2.risk_score
    assert r1.risk_category == r2.risk_category
    assert r1.raw_factors == r2.raw_factors
    assert r1.weighted_contributions == r2.weighted_contributions
    assert r1.breakdown == r2.breakdown


def test_evaluate_risk_custom_policy_version():
    custom_policy = RiskPolicy(
        policy_version="custom-test-v2",
        weight_severity=0.50,
        weight_volume=0.10,
        weight_recurrence=0.20,
        weight_centrality=0.10,
        weight_criticality=0.10,
    )
    result = evaluate_risk(
        {
            "attack_classification": "Ransomware",
            "anomalies": [{"source_ip": "10.0.0.5", "destination_port": 445}],
            "historical_recurrence": 0,
            "graph_centrality": 0.0,
        },
        policy=custom_policy,
    )
    assert result.policy_version == "custom-test-v2"
    assert result.risk_score >= 50


def test_policy_immutability():
    policy = RiskPolicy()
    with pytest.raises((TypeError, ValidationError)):
        policy.policy_version = "mutated-v2"  # type: ignore[misc]

    # Nested mappings cannot be mutated
    with pytest.raises(TypeError):
        policy.classification_severities["Ransomware"] = 50  # type: ignore[index]


def test_policy_weight_validation():
    # Weights must sum to 1.0
    with pytest.raises(ValidationError, match="Weights must sum to 1.0"):
        RiskPolicy(
            weight_volume=0.50,
            weight_severity=0.50,
            weight_recurrence=0.50,
            weight_centrality=0.10,
            weight_criticality=0.10,
        )

    # Weights cannot be negative
    with pytest.raises(ValidationError):
        RiskPolicy(
            weight_volume=-0.10,
            weight_severity=0.35,
            weight_recurrence=0.25,
            weight_centrality=0.25,
            weight_criticality=0.25,
        )


def test_policy_severity_and_criticality_bounds():
    with pytest.raises(ValidationError, match="Severity scores must be between 0 and 100"):
        RiskPolicy(classification_severities={"Ransomware": 150})

    with pytest.raises(ValidationError, match="Criticality scores must be between 0 and 100"):
        RiskPolicy(port_criticalities={22: -5})


@pytest.mark.parametrize(
    ("score_input", "expected_category"),
    [
        (0, "Low"),
        (39, "Low"),
        (40, "Medium"),
        (59, "Medium"),
        (60, "High"),
        (79, "High"),
        (80, "Critical"),
        (100, "Critical"),
    ],
)
def test_category_boundary_mapping(score_input: int, expected_category: str):
    # Construct a policy where criticality has weight 1.0 and defaults to score_input
    boundary_policy = RiskPolicy(
        weight_volume=0.0,
        weight_severity=0.0,
        weight_recurrence=0.0,
        weight_centrality=0.0,
        weight_criticality=1.0,
        default_port_criticality=score_input,
    )
    res = evaluate_risk(
        {"anomalies": [{"source_ip": "1.1.1.1"}], "attack_classification": "Port Scan"},
        policy=boundary_policy,
    )
    assert res.risk_score == score_input
    assert res.risk_category == expected_category


def test_handling_invalid_and_out_of_range_inputs():
    res = evaluate_risk(
        {
            "attack_classification": "Brute Force",
            "anomalies": [
                {"source_ip": "10.0.0.1", "destination_port": "not-a-port"},
                {"source_ip": "10.0.0.2", "destination_port": None},
                "not-a-dict",  # Should be safely ignored
            ],
            "historical_recurrence": 9999,  # Clamped to 100
            "graph_centrality": -50.0,  # Clamped to 0.0
        }
    )
    assert 0 <= res.risk_score <= 100
    assert res.raw_factors["recurrence"] == 100.0
    assert res.raw_factors["centrality"] == 0.0


def test_breakdown_contains_both_raw_and_weighted():
    payload = {
        "attack_classification": "DDoS",
        "anomalies": [{"source_ip": "10.0.0.1", "destination_port": 80} for _ in range(20)],
        "historical_recurrence": 50,
        "graph_centrality": 40.0,
    }
    res = evaluate_risk(payload, policy=DEFAULT_RISK_POLICY)
    # Check raw factors
    assert res.raw_factors["volume"] == 100.0
    assert res.raw_factors["severity"] == 90.0
    assert res.raw_factors["recurrence"] == 50.0
    assert res.raw_factors["centrality"] == 40.0
    assert res.raw_factors["criticality"] == 60.0

    # Check weighted contributions
    assert res.weighted_contributions["volume"] == 100.0 * 0.25
    assert res.weighted_contributions["severity"] == 90.0 * 0.25
    assert res.weighted_contributions["recurrence"] == 50.0 * 0.20
    assert res.weighted_contributions["centrality"] == 40.0 * 0.15
    assert res.weighted_contributions["criticality"] == 60.0 * 0.15

    # Backward compatible breakdown property
    assert res.breakdown == res.raw_factors
