# Phase 1 Implementation Report

**Date:** 25 October 2026

**Plan slice:** Repository hygiene, packaging, runtime, and CI
**Status:** Complete

## Purpose

This report records the Phase 1 changes made to establish a reproducible Zylar
development baseline. It does not certify the application as production-ready.
The next slices are still required for canonical event contracts, security,
local-only inference, PostgreSQL persistence, workflow recovery, and operations.

## Changes delivered

### Reproducible development environment

- Created a local Python 3.12 virtual environment at `.venv/`. It is ignored
  and is not part of source control.
- Added [pyproject.toml](../../pyproject.toml) with the Python support range
  (`>=3.11,<3.13`), pinned direct runtime/development dependencies, build
  configuration, pytest coverage settings, Ruff, mypy, and Pyright settings.
- Kept [requirements.txt](../../requirements.txt) as a compatibility entry
  point that delegates to the project metadata.
- Added a GitHub Actions CI job for Python 3.11 and 3.12. It installs the
  package, lints the new package, type-checks it, runs tests, and builds a wheel.

### Repository hygiene

- Added [.gitignore](../../.gitignore) coverage for virtual environments,
  bytecode, local databases, reports, test/build output, temporary files, and
  local model artefacts.
- Added [.env.example](../../.env.example) with safe local placeholders for
  service URLs, the database URL, request/batch limits, logging, Ollama, and
  the future authentication signing key.
- Updated [README.md](../../README.md) with current prototype status,
  PowerShell setup instructions, quality commands, and accurate limitations.
  It no longer makes unsupported production-ready, autonomous-remediation, or
  self-evolving claims.

### Application foundation

- Added the initial `src/zylar/` package boundary without moving or rewriting
  the legacy agent implementation in one change.
- Added typed, cached settings in
  [src/zylar/core/settings.py](../../src/zylar/core/settings.py). The settings
  use the `ZYLAR_` environment-variable prefix and can read a local `.env` file.
- Added structured JSON logging in
  [src/zylar/core/logging.py](../../src/zylar/core/logging.py). It emits safe
  identifiers such as request, execution, and incident IDs without logging full
  event payloads by default.
- Replaced hardcoded service URLs and Ollama model names in the API, dashboard,
  simulator, threat agent, mitigation agent, and legacy classifier with typed
  settings.

## Validation evidence

The following commands were run from the project `.venv` on 25 October 2026:

| Command | Result | What it proves |
| --- | --- | --- |
| `python -m pip check` | Passed | Installed package metadata has no broken requirements. |
| `python -m ruff check src/zylar` | Passed | The new application package meets the configured lint rules. |
| `python -m mypy src/zylar` | Passed | The new settings/logging package passes the configured static type check. |
| `python -m pytest -q` | Passed: 5 tests | Existing anomaly tests and new settings/logging tests pass. Coverage for `src/zylar` is 85%. |
| `python -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .` | Passed | The project metadata builds a Zylar wheel. |
| `git diff --check` | Passed | No whitespace errors remain in the pending change set. |

## Tests added

[tests/test_settings.py](../../tests/test_settings.py) adds two tests:

1. Safe local defaults load through the typed settings boundary.
2. Structured logging preserves safe correlation identifiers and excludes an
   event payload containing a password-like field.

## Intentional deferrals

These remain outside Phase 1 and must not be presented as complete:

- The legacy `ChatOpenAI` classifier remains until the Phase 4 Ollama-only
  adapter and deterministic fallback are implemented. Its model configuration
  is centralized now to remove the source-level hardcode.
- Legacy modules are not yet subject to the new mypy/Ruff CI gates. The gates
  currently enforce quality for `src/zylar`; legacy migration happens in later
  slices.
- Authentication/RBAC, request limits, safe API errors, dependency health, and
  FastAPI lifespan ownership are Phase 3 work.
- SQLite remains the prototype persistence layer until the Phase 5 PostgreSQL
  migration.
- The repository has not yet received an immutable, fully transitive lockfile;
  direct dependencies are pinned and validated in this slice.

## Phase 2 handoff

Begin canonical event contracts and simulator alignment:

1. Add `NormalizedEvent` and workflow request/response Pydantic models under
   `src/zylar/domain/`.
2. Normalize source events at ingestion and make `user` the only internal user
   field.
3. Add structured `destination_port` support to simulator port-scan events.
4. Add regression fixtures and tests for malformed events, duplicate IDs,
   timestamps, port ranges, correlation, and risk scoring.

## Release statement

Phase 1 establishes a reproducible development baseline. Zylar remains a
functional prototype, not a production-certified SOC platform.
