"""Unit and regression tests for the detection evaluation benchmark suite.

Validates metric calculations, edge case division safeguards, latency percentiles,
corpus schema integrity, and threshold acceptance on the synthetic benchmark.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.evaluate_detection import (
    calculate_classification_metrics,
    calculate_latency_stats,
    run_benchmark,
)

from zylar.analysis.detection_rules import RULES_VERSION
from zylar.analysis.risk_scoring import DEFAULT_RISK_POLICY


@pytest.fixture
def corpus_fixture_path() -> Path:
    return Path(__file__).parents[1] / "fixtures" / "synthetic_evaluation_corpus.json"


@pytest.fixture
def corpus_data(corpus_fixture_path: Path) -> dict:
    assert corpus_fixture_path.exists(), f"Corpus fixture missing at {corpus_fixture_path}"
    with open(corpus_fixture_path, encoding="utf-8") as f:
        return json.load(f)


def test_corpus_schema_and_scenario_counts(corpus_data: dict):
    assert corpus_data["corpus_version"] == "2026.10.1"
    assert corpus_data["total_scenarios"] == 150
    scenarios = corpus_data["scenarios"]
    assert len(scenarios) == 150

    benign = [s for s in scenarios if s["label"] == "benign"]
    bf = [s for s in scenarios if s["label"] == "brute_force"]
    ps = [s for s in scenarios if s["label"] == "port_scan"]
    rw = [s for s in scenarios if s["label"] == "ransomware"]

    assert len(benign) == 100
    assert len(bf) == 20
    assert len(ps) == 20
    assert len(rw) == 10

    for s in scenarios:
        assert "scenario_id" in s
        assert "expected_attack" in s
        assert "expected_rule" in s
        assert "events" in s
        assert isinstance(s["events"], list)
        for ev in s["events"]:
            assert "event_id" in ev
            assert "timestamp" in ev


def test_metric_calculations_division_safeguards():
    # All zero inputs
    res_zero = calculate_classification_metrics(0, 0, 0, 0)
    assert res_zero.precision == 0.0
    assert res_zero.recall == 0.0
    assert res_zero.f1_score == 0.0
    assert res_zero.false_positive_rate == 0.0
    assert res_zero.precision_denominator == 0
    assert res_zero.recall_denominator == 0
    assert res_zero.fpr_denominator == 0

    # No positives (TP=0, FP=0, TN=10, FN=5)
    res_no_pos = calculate_classification_metrics(0, 0, 10, 5)
    assert res_no_pos.precision == 0.0
    assert res_no_pos.recall == 0.0
    assert res_no_pos.precision_denominator == 0
    assert res_no_pos.recall_denominator == 5
    assert res_no_pos.fpr_denominator == 10

    # Custom known values
    res = calculate_classification_metrics(true_positives=45, false_positives=5, true_negatives=95, false_negatives=5)
    assert res.precision == 0.90
    assert res.recall == 0.90
    assert res.f1_score == 0.90
    assert res.false_positive_rate == round(5 / 100, 4)


def test_latency_stats_distribution():
    empty_stats = calculate_latency_stats([], methodology="test")
    assert empty_stats.total_samples == 0
    assert empty_stats.mean_ms == 0.0
    assert empty_stats.p50_ms == 0.0

    samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    stats = calculate_latency_stats(samples, methodology="unit_test")
    assert stats.total_samples == 10
    assert stats.mean_ms == 5.5
    assert stats.min_ms == 1.0
    assert stats.max_ms == 10.0
    assert stats.p50_ms <= stats.p95_ms <= stats.p99_ms


def test_synthetic_evaluation_benchmark_targets(corpus_data: dict):
    report = run_benchmark(corpus_data)

    assert report["metadata"]["corpus_version"] == "2026.10.1"
    assert report["metadata"]["rules_version"] == RULES_VERSION
    assert report["metadata"]["risk_policy_version"] == DEFAULT_RISK_POLICY.policy_version
    assert report["metadata"]["total_scenarios_evaluated"] == 150

    targets = report["target_thresholds"]
    assert targets["precision"]["passed"] is True
    assert targets["precision"]["actual"] >= 0.90

    assert targets["recall"]["passed"] is True
    assert targets["recall"]["actual"] >= 0.85

    assert targets["f1_score"]["passed"] is True
    assert targets["f1_score"]["actual"] >= 0.87

    assert targets["false_positive_rate"]["passed"] is True
    assert targets["false_positive_rate"]["actual"] <= 0.05

    assert targets["all_passed"] is True


def test_benchmark_deterministic_reproducibility(corpus_data: dict):
    run1 = run_benchmark(corpus_data)
    run2 = run_benchmark(corpus_data)

    assert run1["overall_metrics"] == run2["overall_metrics"]
    assert run1["per_rule_metrics"] == run2["per_rule_metrics"]
    assert run1["target_thresholds"] == run2["target_thresholds"]


def test_per_rule_metrics_isolation(corpus_data: dict):
    report = run_benchmark(corpus_data)
    per_rule = report["per_rule_metrics"]

    assert "RULE_BRUTE_FORCE_AUTH" in per_rule
    assert "RULE_PORT_SCAN_REJECT" in per_rule
    assert "RULE_RANSOMWARE_INDICATOR" in per_rule

    bf = per_rule["RULE_BRUTE_FORCE_AUTH"]
    assert bf["true_positives"] == 20
    assert bf["false_positives"] == 0
    assert bf["precision"] == 1.0
    assert bf["recall"] == 1.0

    ps = per_rule["RULE_PORT_SCAN_REJECT"]
    assert ps["true_positives"] == 20
    assert ps["false_positives"] == 0
    assert ps["precision"] == 1.0
    assert ps["recall"] == 1.0

    rw = per_rule["RULE_RANSOMWARE_INDICATOR"]
    assert rw["true_positives"] == 10
    assert rw["false_positives"] == 0
    assert rw["precision"] == 1.0
    assert rw["recall"] == 1.0


def test_benchmark_risk_scoring_validation(corpus_data: dict):
    report = run_benchmark(corpus_data)
    assert report["metadata"]["evaluation_scope"] == "scenario-level"
    assert "risk_scoring_validation" in report

    risk_val = report["risk_scoring_validation"]
    assert risk_val["mean_attack_risk_score"] > 30.0
    assert risk_val["mean_benign_risk_score"] == 0.0
    assert risk_val["risk_categories_count"]["Medium"] > 0
    assert risk_val["risk_categories_count"]["Low"] == 119

    per_class = risk_val["per_attack_class_summary"]
    assert "Brute Force" in per_class
    assert "Port Scan" in per_class
    assert "Ransomware" in per_class
    assert per_class["Brute Force"]["evaluated_count"] == 20
    assert per_class["Port Scan"]["evaluated_count"] == 20
    assert per_class["Ransomware"]["evaluated_count"] == 10
    assert per_class["Ransomware"]["mean_risk_score"] == 38.0
    assert per_class["Ransomware"]["low_severity_count"] == 10



def test_generator_byte_for_byte_reproducibility():
    from scripts.generate_synthetic_corpus import generate_corpus

    c1 = generate_corpus()
    c2 = generate_corpus()

    j1 = json.dumps(c1, indent=2, sort_keys=True)
    j2 = json.dumps(c2, indent=2, sort_keys=True)
    assert j1 == j2
