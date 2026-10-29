# Zylar Phase 6 — Detection Quality & Observability Benchmark Report

> [!IMPORTANT]
> **Synthetic Evaluation Disclosure**: This benchmark is a synthetic evaluation based on a deterministic labeled corpus (tests/fixtures/synthetic_evaluation_corpus.json). It measures rule engine logic against modeled scenarios and does NOT represent measured real-world Security Operations Center (SOC) performance in production enterprise networks.

## 1. Benchmark Execution Metadata

| Parameter | Value |
| :--- | :--- |
| **Evaluation Date (UTC)** | `2026-10-29T16:26:34.823908+00:00` |
| **Corpus Version** | `2026.10.1` |
| **Rules Engine Version** | `2026.10.1` |
| **Risk Policy Version** | `risk-policy-v1` |
| **Total Scenarios Evaluated** | `150` |
| **Overall Target Acceptance** | **PASS** |

---

## 2. Target Thresholds vs. Measured Results

| Metric | Target Threshold | Actual Measured | Explicit Denominator Formula | Status |
| :--- | :---: | :---: | :--- | :---: |
| **Precision** | $\ge 0.90$ | **1.0000** | $TP / (TP + FP) = 50 / 50$ | **PASS** |
| **Recall** | $\ge 0.85$ | **1.0000** | $TP / (TP + FN) = 50 / 50$ | **PASS** |
| **F1 Score** | $\ge 0.87$ | **1.0000** | $2 \times (P \times R) / (P + R)$ | **PASS** |
| **False Positive Rate (FPR)** | $\le 0.05$ | **0.0000** | $FP / (FP + TN) = 0 / 100$ | **PASS** |

---

## 3. Global Confusion Matrix

| Metric Item | Count | Explicit Meaning / Denominator |
| :--- | :---: | :--- |
| **True Positives (TP)** | `50` | True attack correctly identified as attack |
| **False Positives (FP)** | `0` | Benign traffic incorrectly labeled as attack |
| **True Negatives (TN)** | `100` | Benign traffic correctly labeled as benign |
| **False Negatives (FN)** | `0` | True attack missed by detection rules |
| **Total Scenarios** | `150` | $TP + FP + TN + FN$ |

---

## 4. Per-Rule Detection Breakdown

| Rule ID | Rule Focus | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `RULE_BRUTE_FORCE_AUTH` | Repeated auth failure sliding window | `20` | `0` | `130` | `0` | `1.0000` | `1.0000` | `1.0000` | `0.0000` |
| `RULE_PORT_SCAN_REJECT` | Multi-port network probing window | `20` | `0` | `130` | `0` | `1.0000` | `1.0000` | `1.0000` | `0.0000` |
| `RULE_RANSOMWARE_INDICATOR` | Mass encryption & file extension indicators | `10` | `0` | `140` | `0` | `1.0000` | `1.0000` | `1.0000` | `0.0000` |

---

## 5. Detection Latency Measurements

**Methodology**: Measurements taken using Python's high-resolution monotonic timer (`time.perf_counter_ns`) in-process for each scenario.

| Evaluation Stage | Mean (ms) | p50 Median (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) | Samples |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule Engine (`evaluate_detection_rules`)** | `0.0378` | `0.0207` | `0.0789` | `0.0982` | `0.0073` | `1.1192` | `150` |
| **End-to-End (Rules + Risk Scoring)** | `0.0535` | `0.0286` | `0.0925` | `0.3147` | `0.0168` | `1.6747` | `150` |
