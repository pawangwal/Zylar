# Zylar Phase 6 — Detection Quality & Observability Benchmark Report

> [!IMPORTANT]
> **Synthetic Evaluation Disclosure**: This benchmark is a synthetic evaluation based on a deterministic labeled corpus (tests/fixtures/synthetic_evaluation_corpus.json). It measures scenario-level rule engine logic and deterministic risk scoring against modeled scenarios. It does NOT represent measured real-world Security Operations Center (SOC) performance in production enterprise networks.

## 1. Benchmark Execution Metadata

| Parameter | Value |
| :--- | :--- |
| **Evaluation Date (UTC)** | `2026-10-30T11:47:09.120027+00:00` |
| **Corpus Version** | `2026.10.1` |
| **Rules Engine Version** | `2026.10.1` |
| **Risk Policy Version** | `risk-policy-v1` |
| **Total Scenarios Evaluated** | `150` |
| **Overall Target Acceptance** | **PASS** |

---

## 2. Target Thresholds vs. Measured Scenario-Level Results

| Metric | Target Threshold | Actual Measured | Explicit Denominator Formula | Status |
| :--- | :---: | :---: | :--- | :---: |
| **Scenario Precision** | $\ge 0.90$ | **1.0000** | $TP / (TP + FP) = 50 / 50$ | **PASS** |
| **Scenario Recall** | $\ge 0.85$ | **1.0000** | $TP / (TP + FN) = 50 / 50$ | **PASS** |
| **Scenario F1 Score** | $\ge 0.87$ | **1.0000** | $2 \times (P \times R) / (P + R)$ | **PASS** |
| **False Positive Rate (FPR)** | $\le 0.05$ | **0.0000** | $FP / (FP + TN) = 0 / 100$ | **PASS** |

---

## 3. Global Confusion Matrix (Scenario-Level)

| Metric Item | Count | Explicit Meaning / Denominator |
| :--- | :---: | :--- |
| **True Positives (TP)** | `50` | True attack scenario correctly identified as attack |
| **False Positives (FP)** | `0` | Benign scenario incorrectly labeled as attack |
| **True Negatives (TN)** | `100` | Benign scenario correctly labeled as benign |
| **False Negatives (FN)** | `0` | True attack scenario missed by detection rules |
| **Total Scenarios** | `150` | $TP + FP + TN + FN$ |

---

## 4. Per-Rule Detection Breakdown (One-vs-Rest Scenario Level)

| Rule ID | Rule Focus | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `RULE_BRUTE_FORCE_AUTH` | Repeated auth failure sliding window | `20` | `0` | `130` | `0` | `1.0000` | `1.0000` | `1.0000` | `0.0000` |
| `RULE_PORT_SCAN_REJECT` | Multi-port network probing window | `20` | `0` | `130` | `0` | `1.0000` | `1.0000` | `1.0000` | `0.0000` |
| `RULE_RANSOMWARE_INDICATOR` | Mass encryption & file extension indicators | `10` | `0` | `140` | `0` | `1.0000` | `1.0000` | `1.0000` | `0.0000` |

---

## 5. Risk Scoring Engine Verification & Severity Breakdown

> [!NOTE]
> **Detection Classification vs. Operational Severity**: Detection classification identifies the attack technique (100% recall), whereas risk scoring quantifies incident operational impact using multi-factor weights (severity, volume, recurrence, centrality, and port criticality). Isolated boundary attacks with zero recurrence and low centrality legitimately receive Low operational risk scores (< 40).

| Parameter | Measured Value | Description |
| :--- | :---: | :--- |
| **Mean Attack Risk Score** | `41.5/100` | Average score across detected attacks with classification |
| **Mean Benign Risk Score** | `0.0/100` | Baseline score across benign scenarios (guaranteed 0) |
| **Critical Incidents Identified** | `0` | Scores $\ge 80$ |
| **High Risk Incidents Identified** | `0` | Scores $60\text{--}79$ |
| **Medium Risk Incidents Identified** | `31` | Scores $40\text{--}59$ |
| **Low Operational Risk Incidents** | `119` | Scores $< 40$ (including benign baselines and isolated probes) |

### Risk Score Distribution by Attack Category

| Attack Category | Scenarios | Mean Score | Min Score | Max Score | Critical | High | Medium | Low |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Brute Force` | `20` | `41.0` | `36` | `45` | `0` | `0` | `15` | `5` |
| `Port Scan` | `20` | `43.8` | `37` | `51` | `0` | `0` | `16` | `4` |
| `Ransomware` | `10` | `38.0` | `38` | `38` | `0` | `0` | `0` | `10` |

---

## 6. Detection Latency Measurements

**Methodology**: Measurements taken using Python's high-resolution monotonic timer (`time.perf_counter_ns`) in-process for each scenario, preceded by a warmup cycle across both rules and risk scoring.

| Evaluation Stage | Mean (ms) | p50 Median (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) | Samples |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule Engine (`evaluate_detection_rules`)** | `0.0474` | `0.0277` | `0.1202` | `0.2129` | `0.0130` | `0.3514` | `150` |
| **End-to-End (Rules + Risk Scoring)** | `0.0733` | `0.0404` | `0.1635` | `0.2842` | `0.0240` | `1.1248` | `150` |
