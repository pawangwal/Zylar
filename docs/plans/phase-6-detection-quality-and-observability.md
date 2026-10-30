# Phase 6: Detection Quality, Deterministic Risk Scoring & SOC Observability Specification

**Status:** Completed & Production-Hardened  
**Target Environment:** Python 3.12, PostgreSQL 16 (Port 5434), Elasticsearch 8.x, Streamlit, FastAPI  
**Spec Reference:** `docs/zylar-implementation-plan.md` (Slice 7: Detection quality, risk/correlation and observability)

---

## 1. Executive Summary & Objectives

Phase 6 elevates Zylar from an exploratory prototype into a production-grade, measurable, and observable autonomous SOC detection engine. It delivers:

1. **Deterministic Risk Scoring:** Pure functional, versioned risk scoring (`RiskPolicyV1`) guaranteeing exact integer score reproducibility [0–100] and immutable result mappings.
2. **Deterministic Sliding-Window Rules:** Separates statistical anomaly leads (investigative context) from deterministic attack rules (Brute Force, Port Scan, Ransomware) evaluated across sliding time windows.
3. **Bounded Threat Correlation Service:** Resource-capped NetworkX entity graphs with centrality calculations, explicit truncation metadata, and safe Graphviz DOT output encoding without destructive keyword stripping.
4. **Reproducible Evaluation Benchmark:** 150-scenario labeled synthetic evaluation corpus measuring Precision, Recall, F1, FPR, and latency with per-attack-class operational risk disclosures.
5. **Standardized Prometheus Telemetry:** Prometheus exposition format (`/metrics`) exposing 4 segregated lifecycle counters, validated latency histograms, and rule-firing metrics with explicit semantic distinction between pipeline execution and durable persistence.
6. **Resilient Analyst Dashboard:** Streamlit SOC interface displaying dependency health, ingestion watermark lag, lifecycle event columns, failure state alerts, and explicit graph truncation causes.
7. **Cross-Contract Integration Verification:** 9 automated integration tests with context-managed test isolation validating the complete contract from event ingestion to threat graph visualization.

---

## 2. Architecture & Delivered Components

```
                   +-------------------------------------------------+
                   |           Normalized SOC Event Stream           |
                   +-----------------------+-------------------------+
                                           |
                                           v
                   +-------------------------------------------------+
                   |        Sliding-Window Feature Engine            |
                   |   (Time Bounding, Key Aggregation, Rate Ratios) |
                   +-----------------------+-------------------------+
                                           |
                        +------------------+------------------+
                        |                                     |
                        v                                     v
         +-----------------------------+       +-----------------------------+
         | Statistical Anomaly Leads   |       | Deterministic Attack Rules  |
         | (Isolation Forest Outliers) |       | (Brute Force, Port Scan,    |
         +--------------+--------------+       |  Ransomware Indicator)      |
                        |                      +--------------+--------------+
                        +------------------+------------------+
                                           |
                                           v
                   +-------------------------------------------------+
                   |        Versioned Deterministic Risk Engine      |
                   |   - Policy-driven normalized factor weights     |
                   |   - Strict category ordering validation         |
                   |   - Immutable breakdown mappings                |
                   +-----------------------+-------------------------+
                                           |
                        +------------------+------------------+
                        |                                     |
                        v                                     v
         +-----------------------------+       +-----------------------------+
         |  Prometheus Metric Engine   |       |  Bounded Correlation Graph  |
         |  - 4 Lifecycle Counters     |       |  - Node/Edge Resource Caps  |
         |  - Latency Histograms       |       |  - Degree Centrality        |
         |  - Rule Fire Accumulators   |       |  - DOT Output Encoding      |
         +-----------------------------+       +-----------------------------+
```

---

## 3. Component Details & Deliverables

### Task 1: Deterministic Risk Scoring Engine & Policy Versioning
- **Core Module:** `src/zylar/analysis/risk_scoring.py`
- **Adapters:** `agents/risk_agent.py`, `agents/report_agent.py`
- **Tests:** `tests/unit/test_risk_scoring_engine.py`, `tests/unit/test_risk_scoring.py`
- **Key Capabilities:**
  - Evaluates five normalized risk factors: attack severity ($0.25$), event volume ($0.25$), historical recurrence ($0.20$), graph centrality ($0.15$), and port criticality ($0.15$).
  - Policy configuration (`RiskPolicy`) validates weight normalization ($\sum w_i = 1.0$), non-negative bounds, and strictly ascending category boundaries:
    $$\text{Low} < \text{Medium} < \text{High} < \text{Critical}$$
  - Returns `RiskScoreResult` with integer score [0–100], bounded category, active policy version, and immutable `MappingProxyType` breakdown mappings.
  - Guarantees byte-for-byte deterministic reproducibility for identical inputs and policy versions.

### Task 2: Deterministic Detection Rules & Sliding-Window Feature Engine
- **Core Module:** `src/zylar/analysis/detection_rules.py`
- **Adapters:** `agents/anomaly_agent.py`, `agents/classifier_agent.py`
- **Tests:** `tests/unit/test_detection_rules.py`
- **Key Capabilities:**
  - Separates statistical Isolation Forest anomaly scores (candidate investigative signals) from deterministic attack rules.
  - Implements sliding time-window feature aggregation:
    - `RULE_BRUTE_FORCE_AUTH`: $\ge 5$ failed authentications within 120 seconds.
    - `RULE_PORT_SCAN_REJECT`: $\ge 10$ unique destination ports contacted within 60 seconds with $\ge 80\%$ rejection rate.
    - `RULE_RANSOMWARE_INDICATOR`: file extension (.locked, .encrypted) or ransomware keywords on individual events.
    - `RULE_RANSOMWARE_MASS_ENCRYPTION`: $\ge 20$ file encryption/modification events per entity within sliding window (300 seconds).
  - Enforces deterministic tie-breaking and sorting by timestamp and event ID.

### Task 3: Typed Correlation Graph Service & Safe Serialization
- **Core Module:** `src/zylar/analysis/correlation_service.py`
- **API Endpoint:** `GET /api/threat-graph` in `api/main.py`
- **Tests:** `tests/unit/test_correlation_service.py`
- **Key Capabilities:**
  - Bounded NetworkX entity graph construction enforcing strict limits: `max_events=500`, `max_nodes=250`, `max_edges=600`.
  - Calculates degree and betweenness centrality to identify top network hubs and pivot entities.
  - Safe Graphviz DOT output encoding (`_escape_dot_label`):
    - Escapes backslashes (`\\`), double quotes (`\"`), newlines (`\n`), carriage returns (`\r`), and tabs (`\t`).
    - Strips unprintable control characters (`\x00`–`\x1f`, `\x7f`–`\x9f`) to prevent terminal and lexer injection.
    - Preserves data identifiers with complete fidelity without destructive regex keyword stripping.
  - Returns explicit truncation metadata: `input_event_count`, `processed_event_count`, `event_limit_reached`, `node_limit_reached`, `edge_limit_reached`, and `is_truncated`.
  - Upstream backend error translation: Elasticsearch connection and timeout errors return `HTTP 502 Bad Gateway` rather than masking failures with an empty graph.

### Task 4: Detection Evaluation Benchmark Suite
- **Corpus Generator:** `scripts/generate_synthetic_corpus.py`
- **Evaluation Runner:** `scripts/evaluate_detection.py`
- **Corpus Fixture:** `tests/fixtures/synthetic_evaluation_corpus.json`
- **Reports:** `docs/reports/phase-6-detection-evaluation.json`, `docs/reports/phase-6-detection-evaluation.md`
- **Tests:** `tests/evaluation/test_benchmark_metrics.py`
- **Key Capabilities:**
  - Immutable 150-scenario labeled corpus: 100 benign, 20 brute force, 20 port scan, 10 ransomware.
  - Dual-engine warmups (rules and risk scoring) to eliminate cold-start timing jitter.
  - Generates comprehensive classification metrics:
    - Precision: **1.0000**
    - Recall: **1.0000**
    - F1-Score: **1.0000**
    - False Positive Rate: **0.0000**
    - Detection Latency: Mean $0.0474$ ms, P95 $0.0818$ ms
    - Risk Scoring Latency: Mean $0.0195$ ms, P95 $0.0336$ ms
  - Discloses per-attack-class risk summary explaining operational severity vs detection recall: boundary attacks with zero recurrence and low centrality legitimately receive Low operational risk scores ($< 40$) despite 100% detection recall.

### Task 5: Prometheus Operational Telemetry
- **Core Accumulator:** `src/zylar/core/metrics.py`
- **API Endpoint:** `GET /metrics` in `api/main.py`
- **Tests:** `tests/api/test_metrics_endpoint.py`
- **Key Capabilities:**
  - Segregates 4 distinct lifecycle event counters:
    - `zylar_events_received_total`: Events ingested at poll or API boundary.
    - `zylar_events_processed_total`: Events committed to PostgreSQL in an atomic transaction with advanced checkpoint.
    - `zylar_events_deduplicated_total`: Duplicate/replay events filtered by compound cursor.
    - `zylar_events_quarantined_total`: Malformed/poison events stored in `dead_letter_events`.
  - Strict histogram bucket validation: positive, monotonically increasing values with terminal `+Inf`.
  - Explicit metric semantics distinction documented:
    - `zylar_workflow_executions_total`: LangGraph pipeline inference/analysis execution.
    - `zylar_events_processed_total`: Durable database persistence and watermark advancement.

### Task 6: Resilient SOC Dashboard Observability
- **Dashboard Module:** `dashboard/app.py`
- **Tests:** `tests/unit/test_dashboard.py`
- **Key Capabilities:**
  - Connects to `/health/ready`, `/api/ingestion/status`, `/metrics`, and `/api/threat-graph` with strict $3.0$-second timeouts.
  - Displays 4-column event lifecycle telemetry metrics.
  - Monitors checkpoint watermark and active ingestion lag seconds.
  - Renders dependency degradation banners and explicit error states for threat graph outages (HTTP 502/503).
  - Reports detailed graph truncation causes based on canonical boolean flags.

### Task 7: Cross-Contract Integration Suite
- **Module:** `tests/integration/test_phase6_cross_contract.py`
- **Key Capabilities:**
  - 9 automated end-to-end integration tests using isolated context-managed clients (`with TestClient(app) as client:`).
  - Exercises `CheckpointedIngestionWorker` against real PostgreSQL and mocked Elasticsearch for lease acquisition, compound cursor pagination, duplicate skipping, poison quarantine, and error recovery clearing `_last_error`.
  - Validates FastAPI lifespan background scheduler across `active`, `stopped`, and `offline` lifecycle states.
  - Verifies HTTP 502 Bad Gateway error semantics on search backend failure.

---

## 4. Post-Review Remediation Summary

| Review Finding | Action Taken | Verification |
| :--- | :--- | :--- |
| **Conflated event counters** | Segregated into 4 distinct lifecycle counters (`received`, `processed`, `deduplicated`, `quarantined`) with backward-compatibility aliases. | Verified in `test_metrics_endpoint.py` and `test_phase6_cross_contract.py`. |
| **Missing real worker integration test** | Implemented 4 `CheckpointedIngestionWorker` integration tests exercising real PostgreSQL transactions, cursors, dedup, and dead-letter quarantine. | All 4 worker integration tests pass cleanly. |
| **Threat graph masked errors (HTTP 200)** | Mapped upstream Elasticsearch connection/timeout failures directly to `HTTP 502 Bad Gateway`. | Verified in `test_threat_graph_upstream_error_semantics`. |
| **Implicit threat graph truncation** | Added explicit boolean flags (`event_limit_reached`, `node_limit_reached`, `edge_limit_reached`) and counts to payload. | Verified in `test_correlation_service.py` and `test_phase6_cross_contract.py`. |
| **Unvalidated histogram buckets & durations** | Added `validate_histogram_buckets()` and non-negative finite duration validation. | Verified in `test_metrics_endpoint.py`. |
| **Worker error retention after recovery** | Configured `run_poll_cycle()` to clear `_last_error = None` upon successful or idle recovery while retaining `_last_failed_cycle`. | Verified in `test_worker_error_recovery_clears_last_error`. |
| **Scheduler lifespan test gap** | Tested `active`, `stopped`, and `offline` states using context-managed `TestClient(app)`. | Verified in `test_scheduler_status_lifecycle`. |
| **Benchmark warmup & risk disclosures** | Added dual-engine warmups, per-attack-class risk tables, and operational severity disclosures to benchmark reports. | Verified in `test_benchmark_metrics.py`. |
| **Test isolation (module-level client)** | Replaced module-level `TestClient(app)` with context-managed fixture across all cross-contract tests. | Verified in `test_phase6_cross_contract.py`. |
| **Fragile regex SQL stripping in Graphviz** | Replaced regex keyword stripping with robust Graphviz DOT output encoding (escaped quotes/slashes, stripped unprintable control chars). | Verified in `test_correlation_service.py`. |
| **Configuration inconsistency in .env.example** | Standardized on credential-free Elasticsearch URL `http://127.0.0.1:9200` with separate username/password settings. | Verified in `test_settings.py` and `.env.example`. |

---

## 5. Verification Evidence & Quality Gates

All automated verification gates pass with 100% success against the project environment:

- **Automated Test Suite:** 352 passed, 0 failed, 5 warnings in 91.68s (`pytest -ra`).
- **Code Coverage:** **91% statement coverage** across all `src/zylar` modules.
- **Code Style & Linting:** Clean pass with 0 errors (`ruff check src/zylar api dashboard scripts tests`).
- **Static Type Checking:** Clean pass with 0 errors across 24 source files (`mypy src/zylar`).
- **Wheel Packaging:** Successfully built distribution artifact `dist/zylar-0.1.0-py3-none-any.whl`.
