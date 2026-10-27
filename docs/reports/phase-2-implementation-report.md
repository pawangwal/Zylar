.venvs# Phase 2 Implementation Report

**Date:** 26 October 2026

**Plan slice:** Canonical event model and simulator alignment
**Status:** Complete

## Purpose

This report records the Phase 2 changes delivered to establish a single, validated
security event contract across ingestion, simulation, anomaly detection, correlation,
risk scoring, and workflow orchestration.

## Changes delivered

### Canonical domain models

- Created [src/zylar/domain/events.py](../../src/zylar/domain/events.py) defining:
  - `NormalizedEvent`: Enforces non-empty stable `event_id`, timezone-aware UTC
    normalization, IPv4/IPv6 validation for `source_ip`, canonical `user` field,
    port range validation (`1..65535`), length limits, and deterministic SHA-256
    `raw_event_hash`.
  - Legacy `username` compatibility: Automatically maps `username` to `user` on input.
  - `EventNormalizer`: Normalizes raw log dictionaries and Elasticsearch `_source`
    hits, resolving `_id` and generating stable documented fallback IDs when absent.
  - `NormalizationResult`: Captures segregated valid `events` and `quarantined` records
    with diagnostic error reasons.
- Created [src/zylar/domain/workflow.py](../../src/zylar/domain/workflow.py) defining
  `WorkflowRequest` with batch boundary limits (`1..1000`) and configurable duplicate
  event ID rejection.
- Created [src/zylar/domain/responses.py](../../src/zylar/domain/responses.py) defining
  standard `IncidentResponse`, `HealthResponse`, `ComponentHealth`, and `ErrorResponse`.
- Exposed all models via [src/zylar/domain/__init__.py](../../src/zylar/domain/__init__.py).

### Ingestion boundary normalization

- Refactored [agents/log_analyzer.py](../../agents/log_analyzer.py) to parse raw logs
  through `EventNormalizer.normalize_batch`. It outputs canonical serialized event
  dictionaries and records quarantined failures into workflow state.
- Updated [agents/state.py](../../agents/state.py) to enable partial LangGraph state
  updates (`total=False`) and capture `quarantined_events`.

### Downstream field consistency

- **Correlation Agent ([agents/correlation_agent.py](../../agents/correlation_agent.py)):**
  - Updated to consume canonical `user` (with backward-compatible `username` fallback).
  - Uses structured numeric `destination_port`.
  - Added operational bounds (`MAX_CORRELATION_EVENTS = 500`, `MAX_GRAPH_NODES = 250`,
    `MAX_GRAPH_EDGES = 600`) to prevent denial-of-service / memory blowup.
- **Risk Agent ([agents/risk_agent.py](../../agents/risk_agent.py)):**
  - Updated to consume canonical `user` for recurrence factors.
  - Evaluates asset criticality using structured `destination_port` integers
    (SSH/RDP `22, 3389` -> 90, HTTP/S `80, 443` -> 70, others -> 50).
- **Anomaly Agent ([agents/anomaly_agent.py](../../agents/anomaly_agent.py)):**
  - Sanitizes Pandas DataFrame conversions to preserve integer ports and replace `NaN`
    values with `None` in downstream anomaly records.

### Simulator alignment & deterministic fixtures

- Updated [log_generator/simulate_attacks.py](../../log_generator/simulate_attacks.py):
  - Emits structured `destination_port` integers for network and port-scan events.
  - Uses timezone-aware UTC timestamps (`datetime.now(datetime.timezone.utc)`).
  - Added deterministic generators for reproducible testing:
    `generate_deterministic_benign_events`, `generate_deterministic_brute_force`,
    `generate_deterministic_port_scan`, and `generate_deterministic_ransomware`.
- Created immutable JSON fixtures:
  - [tests/fixtures/benign_events.json](../../tests/fixtures/benign_events.json)
  - [tests/fixtures/attack_events.json](../../tests/fixtures/attack_events.json)

## Validation evidence

The following verification commands were executed from `.venv` on 26 October 2026:

| Command | Result | What it proves |
| --- | --- | --- |
| `python -m ruff check src/zylar` | Passed | New domain package meets all lint and pyupgrade rules. |
| `python -m mypy src/zylar` | Passed | Strict type checking passes across all 8 package source files. |
| `python -m pytest` | Passed: 30 tests | All anomaly, settings, correlation, validation, and risk tests pass. `src/zylar` coverage is 87%. |
| `python -m pip wheel --no-deps --wheel-dir dist .` | Passed | Package metadata and domain package successfully build into a wheel. |
| `git status` | Clean / verified | All changes isolated to canonical event contracts, simulator alignment, and regression tests. |

## Tests added

- [tests/unit/test_event_validation.py](../../tests/unit/test_event_validation.py):
  13 tests covering UTC offsets, naive timestamp rejection, IPv4/IPv6 validation,
  invalid IP rejection, port range boundaries (`1..65535`), boolean rejection,
  empty ID rejection, legacy `username` mapping, deterministic hashes, and batch duplicate policies.
- [tests/unit/test_event_normalization.py](../../tests/unit/test_event_normalization.py):
  3 tests covering Elasticsearch hit parsing, document `_id` resolution, and batch
  segregation into valid events and quarantined records.
- [tests/unit/test_correlation.py](../../tests/unit/test_correlation.py):
  5 tests covering empty event handling, canonical user/port edge additions, multi-port
  scan centrality, legacy compatibility, and graph resource limits.
- [tests/unit/test_risk_scoring.py](../../tests/unit/test_risk_scoring.py):
  4 tests covering empty state handling, asset criticality port heuristics, canonical
  user propagation to memory, and deterministic score reproducibility.

## Intentional deferrals

- Authentication, RBAC matrix, and rate limiting remain Phase 3 scope.
- Replacing `ChatOpenAI` with a local Ollama client and deterministic fallback remains Phase 3/4 scope.
- PostgreSQL schema and Alembic migrations remain Phase 4/5 scope.
- Workflow checkpointing and worker queues remain Phase 5 scope.

## Phase 3 handoff

Proceed to API Security, Authorization, and Health:
1. Implement authentication and role-based authorization (`admin`, `analyst`, `viewer`).
2. Add input validation limits, safe generic error envelopes, and correlation IDs in FastAPI.
3. Move blocking operations out of async request handlers.
4. Add `/health/live` and `/health/ready` endpoints reflecting actual dependency readiness.
5. Implement local-only Ollama inference adapter and deterministic fallback.
