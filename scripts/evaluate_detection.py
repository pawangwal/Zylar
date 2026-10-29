"""Reproducible Detection Evaluation Benchmark Runner for Zylar SOC Rules.

Evaluates deterministic detection rules against the versioned synthetic corpus,
computes precision, recall, F1, and FPR with explicit denominators, measures
per-scenario detection latency, and produces machine-readable and human-readable reports.

Target Thresholds:
  - Precision >= 0.90
  - Recall    >= 0.85
  - F1        >= 0.87
  - FPR       <= 0.05
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zylar.analysis.detection_rules import (
    RULES_VERSION,
    evaluate_detection_rules,
)
from zylar.analysis.risk_scoring import DEFAULT_RISK_POLICY, evaluate_risk


@dataclass(frozen=True)
class MetricResult:
    """Confusion matrix and classification metrics with explicit denominators."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    total_evaluated: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    precision_denominator: int  # TP + FP
    recall_denominator: int  # TP + FN
    fpr_denominator: int  # FP + TN


@dataclass(frozen=True)
class LatencyStats:
    """Execution latency percentiles and distribution statistics."""

    total_samples: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    methodology: str


def calculate_classification_metrics(
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
) -> MetricResult:
    """Safely calculates precision, recall, F1, and FPR with zero-division safeguards."""
    total = true_positives + false_positives + true_negatives + false_negatives
    precision_denom = true_positives + false_positives
    recall_denom = true_positives + false_negatives
    fpr_denom = false_positives + true_negatives

    precision = true_positives / precision_denom if precision_denom > 0 else 0.0
    recall = true_positives / recall_denom if recall_denom > 0 else 0.0

    if (precision + recall) > 0.0:
        f1 = (2.0 * precision * recall) / (precision + recall)
    else:
        f1 = 0.0

    fpr = false_positives / fpr_denom if fpr_denom > 0 else 0.0

    return MetricResult(
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        total_evaluated=total,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        precision_denominator=precision_denom,
        recall_denominator=recall_denom,
        fpr_denominator=fpr_denom,
    )


def calculate_latency_stats(latencies_ms: list[float], methodology: str) -> LatencyStats:
    """Calculates distribution statistics for latency measurements in milliseconds."""
    if not latencies_ms:
        return LatencyStats(
            total_samples=0,
            mean_ms=0.0,
            p50_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
            min_ms=0.0,
            max_ms=0.0,
            methodology=methodology,
        )

    sorted_vals = sorted(latencies_ms)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        if n == 1:
            return sorted_vals[0]
        rank = p * (n - 1)
        lower = int(math.floor(rank))
        upper = int(math.ceil(rank))
        weight = rank - lower
        return sorted_vals[lower] * (1.0 - weight) + sorted_vals[upper] * weight

    return LatencyStats(
        total_samples=n,
        mean_ms=round(sum(sorted_vals) / n, 4),
        p50_ms=round(percentile(0.50), 4),
        p95_ms=round(percentile(0.95), 4),
        p99_ms=round(percentile(0.99), 4),
        min_ms=round(sorted_vals[0], 4),
        max_ms=round(sorted_vals[-1], 4),
        methodology=methodology,
    )


def run_benchmark(corpus_data: dict[str, Any]) -> dict[str, Any]:
    """Evaluates detection rules and risk scoring across the provided corpus."""
    scenarios = corpus_data.get("scenarios", [])
    corpus_version = corpus_data.get("corpus_version", "unknown")

    # Tracking overall metrics
    overall_tp = 0
    overall_fp = 0
    overall_tn = 0
    overall_fn = 0

    # Tracking per-rule metrics
    rules = [
        "RULE_BRUTE_FORCE_AUTH",
        "RULE_PORT_SCAN_REJECT",
        "RULE_RANSOMWARE_INDICATOR",
    ]
    rule_counts: dict[str, dict[str, int]] = {
        r: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for r in rules
    }

    latencies_rule_eval_ms: list[float] = []
    latencies_end_to_end_ms: list[float] = []

    for scenario in scenarios:
        expected_attack = bool(scenario.get("expected_attack", False))
        expected_rule = scenario.get("expected_rule")
        events = scenario.get("events", [])

        # 1. Measure detection rule evaluation latency
        t0 = time.perf_counter_ns()
        det_result = evaluate_detection_rules(events)
        t1 = time.perf_counter_ns()
        rule_ms = (t1 - t0) / 1_000_000.0
        latencies_rule_eval_ms.append(rule_ms)

        # 2. Measure end-to-end (rules + risk scoring evaluation) latency
        t_risk0 = time.perf_counter_ns()
        scoring_state: dict[str, Any] = {
            "anomalies": events,
            "anomaly_confidence": 0.85 if det_result.is_attack else 0.1,
            "historical_recurrence": 1,
            "graph_centrality": 25.0 if det_result.is_attack else 0.0,
            "statistical_anomalies": det_result.statistical_outliers_count,
            "rule_matches": [rm.model_dump() for rm in det_result.rule_matches],
        }
        _ = evaluate_risk(scoring_state)
        t_risk1 = time.perf_counter_ns()
        e2e_ms = rule_ms + ((t_risk1 - t_risk0) / 1_000_000.0)
        latencies_end_to_end_ms.append(e2e_ms)

        # Update overall confusion matrix
        detected_attack = det_result.is_attack
        if expected_attack and detected_attack:
            overall_tp += 1
        elif expected_attack and not detected_attack:
            overall_fn += 1
        elif not expected_attack and detected_attack:
            overall_fp += 1
        else:
            overall_tn += 1

        # Update per-rule metrics
        matched_rule_ids = {rm.rule_id for rm in det_result.rule_matches}
        for r in rules:
            rule_expected = expected_rule == r
            rule_matched = r in matched_rule_ids
            if rule_expected and rule_matched:
                rule_counts[r]["tp"] += 1
            elif rule_expected and not rule_matched:
                rule_counts[r]["fn"] += 1
            elif not rule_expected and rule_matched:
                rule_counts[r]["fp"] += 1
            else:
                rule_counts[r]["tn"] += 1

    overall_metrics = calculate_classification_metrics(
        overall_tp, overall_fp, overall_tn, overall_fn
    )

    per_rule_metrics = {
        r: calculate_classification_metrics(
            rule_counts[r]["tp"],
            rule_counts[r]["fp"],
            rule_counts[r]["tn"],
            rule_counts[r]["fn"],
        )
        for r in rules
    }

    latency_rule_stats = calculate_latency_stats(
        latencies_rule_eval_ms,
        methodology="In-process monotonic time (time.perf_counter_ns) for evaluate_detection_rules over normalized events",
    )
    latency_e2e_stats = calculate_latency_stats(
        latencies_end_to_end_ms,
        methodology="In-process monotonic time (time.perf_counter_ns) for evaluate_detection_rules + evaluate_risk",
    )

    # Threshold evaluation
    target_precision = 0.90
    target_recall = 0.85
    target_f1 = 0.87
    target_fpr = 0.05

    targets_passed = {
        "precision": bool(overall_metrics.precision >= target_precision),
        "recall": bool(overall_metrics.recall >= target_recall),
        "f1_score": bool(overall_metrics.f1_score >= target_f1),
        "false_positive_rate": bool(overall_metrics.false_positive_rate <= target_fpr),
    }
    all_targets_passed = all(targets_passed.values())

    return {
        "metadata": {
            "evaluation_timestamp": datetime.now(UTC).isoformat(),
            "corpus_version": corpus_version,
            "rules_version": RULES_VERSION,
            "risk_policy_version": DEFAULT_RISK_POLICY.policy_version,
            "total_scenarios_evaluated": len(scenarios),
            "synthetic_evaluation_disclosure": (
                "This benchmark is a synthetic evaluation based on a deterministic labeled corpus "
                "(tests/fixtures/synthetic_evaluation_corpus.json). It measures rule engine logic "
                "against modeled scenarios and does NOT represent measured real-world Security Operations "
                "Center (SOC) performance in production enterprise networks."
            ),
        },
        "target_thresholds": {
            "precision": {"target": target_precision, "actual": overall_metrics.precision, "passed": targets_passed["precision"]},
            "recall": {"target": target_recall, "actual": overall_metrics.recall, "passed": targets_passed["recall"]},
            "f1_score": {"target": target_f1, "actual": overall_metrics.f1_score, "passed": targets_passed["f1_score"]},
            "false_positive_rate": {"target": target_fpr, "actual": overall_metrics.false_positive_rate, "passed": targets_passed["false_positive_rate"]},
            "all_passed": all_targets_passed,
        },
        "overall_metrics": asdict(overall_metrics),
        "per_rule_metrics": {r: asdict(m) for r, m in per_rule_metrics.items()},
        "latency_statistics": {
            "detection_rules_ms": asdict(latency_rule_stats),
            "end_to_end_detection_and_risk_ms": asdict(latency_e2e_stats),
        },
    }


def generate_markdown_report(report_data: dict[str, Any]) -> str:
    """Renders human-readable markdown report with explicit denominators and disclosures."""
    meta = report_data["metadata"]
    targets = report_data["target_thresholds"]
    overall = report_data["overall_metrics"]
    per_rule = report_data["per_rule_metrics"]
    lat_rule = report_data["latency_statistics"]["detection_rules_ms"]
    lat_e2e = report_data["latency_statistics"]["end_to_end_detection_and_risk_ms"]

    def status_badge(p: bool) -> str:
        return "**PASS**" if p else "**FAIL**"

    md = f"""# Zylar Phase 6 — Detection Quality & Observability Benchmark Report

> [!IMPORTANT]
> **Synthetic Evaluation Disclosure**: {meta["synthetic_evaluation_disclosure"]}

## 1. Benchmark Execution Metadata

| Parameter | Value |
| :--- | :--- |
| **Evaluation Date (UTC)** | `{meta["evaluation_timestamp"]}` |
| **Corpus Version** | `{meta["corpus_version"]}` |
| **Rules Engine Version** | `{meta["rules_version"]}` |
| **Risk Policy Version** | `{meta["risk_policy_version"]}` |
| **Total Scenarios Evaluated** | `{meta["total_scenarios_evaluated"]}` |
| **Overall Target Acceptance** | {status_badge(targets["all_passed"])} |

---

## 2. Target Thresholds vs. Measured Results

| Metric | Target Threshold | Actual Measured | Explicit Denominator Formula | Status |
| :--- | :---: | :---: | :--- | :---: |
| **Precision** | $\\ge 0.90$ | **{targets["precision"]["actual"]:.4f}** | $TP / (TP + FP) = {overall["true_positives"]} / {overall["precision_denominator"]}$ | {status_badge(targets["precision"]["passed"])} |
| **Recall** | $\\ge 0.85$ | **{targets["recall"]["actual"]:.4f}** | $TP / (TP + FN) = {overall["true_positives"]} / {overall["recall_denominator"]}$ | {status_badge(targets["recall"]["passed"])} |
| **F1 Score** | $\\ge 0.87$ | **{targets["f1_score"]["actual"]:.4f}** | $2 \\times (P \\times R) / (P + R)$ | {status_badge(targets["f1_score"]["passed"])} |
| **False Positive Rate (FPR)** | $\\le 0.05$ | **{targets["false_positive_rate"]["actual"]:.4f}** | $FP / (FP + TN) = {overall["false_positives"]} / {overall["fpr_denominator"]}$ | {status_badge(targets["false_positive_rate"]["passed"])} |

---

## 3. Global Confusion Matrix

| Metric Item | Count | Explicit Meaning / Denominator |
| :--- | :---: | :--- |
| **True Positives (TP)** | `{overall["true_positives"]}` | True attack correctly identified as attack |
| **False Positives (FP)** | `{overall["false_positives"]}` | Benign traffic incorrectly labeled as attack |
| **True Negatives (TN)** | `{overall["true_negatives"]}` | Benign traffic correctly labeled as benign |
| **False Negatives (FN)** | `{overall["false_negatives"]}` | True attack missed by detection rules |
| **Total Scenarios** | `{overall["total_evaluated"]}` | $TP + FP + TN + FN$ |

---

## 4. Per-Rule Detection Breakdown

| Rule ID | Rule Focus | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `RULE_BRUTE_FORCE_AUTH` | Repeated auth failure sliding window | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["true_positives"]}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["false_positives"]}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["true_negatives"]}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["false_negatives"]}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["precision"]:.4f}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["recall"]:.4f}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["f1_score"]:.4f}` | `{per_rule["RULE_BRUTE_FORCE_AUTH"]["false_positive_rate"]:.4f}` |
| `RULE_PORT_SCAN_REJECT` | Multi-port network probing window | `{per_rule["RULE_PORT_SCAN_REJECT"]["true_positives"]}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["false_positives"]}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["true_negatives"]}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["false_negatives"]}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["precision"]:.4f}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["recall"]:.4f}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["f1_score"]:.4f}` | `{per_rule["RULE_PORT_SCAN_REJECT"]["false_positive_rate"]:.4f}` |
| `RULE_RANSOMWARE_INDICATOR` | Mass encryption & file extension indicators | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["true_positives"]}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["false_positives"]}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["true_negatives"]}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["false_negatives"]}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["precision"]:.4f}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["recall"]:.4f}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["f1_score"]:.4f}` | `{per_rule["RULE_RANSOMWARE_INDICATOR"]["false_positive_rate"]:.4f}` |

---

## 5. Detection Latency Measurements

**Methodology**: Measurements taken using Python's high-resolution monotonic timer (`time.perf_counter_ns`) in-process for each scenario.

| Evaluation Stage | Mean (ms) | p50 Median (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) | Samples |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule Engine (`evaluate_detection_rules`)** | `{lat_rule["mean_ms"]:.4f}` | `{lat_rule["p50_ms"]:.4f}` | `{lat_rule["p95_ms"]:.4f}` | `{lat_rule["p99_ms"]:.4f}` | `{lat_rule["min_ms"]:.4f}` | `{lat_rule["max_ms"]:.4f}` | `{lat_rule["total_samples"]}` |
| **End-to-End (Rules + Risk Scoring)** | `{lat_e2e["mean_ms"]:.4f}` | `{lat_e2e["p50_ms"]:.4f}` | `{lat_e2e["p95_ms"]:.4f}` | `{lat_e2e["p99_ms"]:.4f}` | `{lat_e2e["min_ms"]:.4f}` | `{lat_e2e["max_ms"]:.4f}` | `{lat_e2e["total_samples"]}` |
"""
    return md


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate detection benchmark on synthetic corpus")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).parents[1] / "tests" / "fixtures" / "synthetic_evaluation_corpus.json",
        help="Path to synthetic evaluation corpus JSON",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path(__file__).parents[1] / "docs" / "reports" / "phase-6-detection-evaluation.json",
        help="Path to output evaluation JSON report",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=Path(__file__).parents[1] / "docs" / "reports" / "phase-6-detection-evaluation.md",
        help="Path to output evaluation Markdown report",
    )
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Error: Corpus file not found at {args.corpus}", file=sys.stderr)
        return 1

    with open(args.corpus, encoding="utf-8") as f:
        corpus_data = json.load(f)

    report = run_benchmark(corpus_data)

    # Ensure output directories exist
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)

    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    md_content = generate_markdown_report(report)
    with open(args.output_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    print("=" * 72)
    print("ZYLAR PHASE 6 — SYNTHETIC DETECTION BENCHMARK RESULTS")
    print("=" * 72)
    print(f"Corpus: {args.corpus} (Version {report['metadata']['corpus_version']})")
    print(f"Rules Version: {report['metadata']['rules_version']}")
    print(f"Risk Policy Version: {report['metadata']['risk_policy_version']}")
    print(f"Total Scenarios Evaluated: {report['metadata']['total_scenarios_evaluated']}")
    print("-" * 72)
    targets = report["target_thresholds"]
    for metric, info in targets.items():
        if metric == "all_passed":
            continue
        status = "PASS" if info["passed"] else "FAIL"
        print(f"  {metric:<20}: target {info['target']:>6.2f} | actual {info['actual']:>6.4f} [{status}]")
    print("-" * 72)
    all_ok = targets["all_passed"]
    print(f"Overall Benchmark Acceptance: {'ACCEPTED (PASS)' if all_ok else 'REJECTED (FAIL)'}")
    print("Reports written to:")
    print(f"  JSON: {args.output_json}")
    print(f"  MD:   {args.output_md}")
    print("=" * 72)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
