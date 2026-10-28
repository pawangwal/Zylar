# Phase 5 Hardening & Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve critical correctness, concurrency, and security gaps in Phase 5 checkpointed ingestion and Phase 4 persistence: implement reliable Elasticsearch pagination, atomic single-transaction incident/checkpoint persistence, monotonic lease fencing, exponential retry backoff, dead-letter deduplication, and API/deployment security controls.

**Architecture:** 
1. Ingestion queries Elasticsearch via `search_after` using `(timestamp, event_id.keyword)` to guarantee complete pagination without `_id` metadata sort restrictions or same-timestamp stalls.
2. Ingestion decoupling: workflow graph executes detection in-memory, returning validated DTOs, then persists the incident lifecycle, advances the checkpoint, and releases the lease within a **single atomic PostgreSQL transaction**.
3. Worker leases enforce monotonic `lease_generation` fencing tokens to reject stale worker commits, while `acquire_lease()` honors `next_retry_at` backoff with exponential delay and jitter.
4. Security boundaries: Docker Compose binds services strictly to `127.0.0.1`, validation errors strip raw user inputs, operational status endpoints sanitize exception summaries, audit logging applies a recursive sanitizer (`sanitize_audit_details`), and Graphviz DOT rendering escapes identifiers.

**Tech Stack:** Python 3.12, PostgreSQL 16, SQLAlchemy 2.x, Alembic, Elasticsearch 8.x, FastAPI, Pydantic v2, pytest.

**Spec:** User review document "Zylar — Phase Implementation, Architecture and Security Review" (Priority 0 & Priority 1 items).

## Global Constraints
- Target PostgreSQL database: port `5434`, `zylar_db`.
- No hardcoded credentials anywhere outside `.env` (development) or environment secrets (production). `.env.example` must contain placeholder values only and must match port 5434 and database `zylar_db`.
- Database uniqueness and transaction boundaries remain the concurrency and consistency authority.
- Checkpoints must NEVER advance before the corresponding data has been durably committed.
- No raw exception tracebacks or user input echoed in API responses.
- Docker services in development bind exclusively to `127.0.0.1`.

---

### Task 1: Schema Hardening & Migration 0003

**Files:**
- Modify: `src/zylar/persistence/models.py`
- Create: `alembic/versions/0003_ingestion_hardening.py`
- Test: `tests/integration/test_postgres_migrations.py`

**Interfaces:**
- Produces in `IngestionCheckpointModel`:
  - `lease_generation`: `Mapped[int]` (default 0, nullable=False)
  - `next_retry_at`: `Mapped[datetime | None]` (nullable=True, timezone=True)
  - Check constraints: `chk_checkpoint_status`, `chk_batch_sequence_nonneg`, `chk_lease_generation_nonneg`
- Produces in `DeadLetterEventModel`:
  - `UniqueConstraint("stream_id", "event_id", name="uq_dead_letter_stream_event")`
  - Check constraint: `chk_dead_letter_status` (`status IN ('QUARANTINED', 'REPROCESSED', 'DISCARDED')`)

- [x] **Step 1: Write migration integration test for 0003 upgrade and downgrade**

In `tests/integration/test_postgres_migrations.py`, add `test_migration_0003_applies_fencing_and_constraints()` verifying new columns, check constraints, and unique constraints.

- [x] **Step 2: Update models.py with new columns and constraints**

Update `IngestionCheckpointModel` and `DeadLetterEventModel` in `src/zylar/persistence/models.py` with `lease_generation`, `next_retry_at`, and table check/unique constraints.

- [x] **Step 3: Create Alembic migration script 0003_ingestion_hardening.py**

Create `alembic/versions/0003_ingestion_hardening.py` implementing `op.add_column()`, `op.create_check_constraint()`, and `op.create_unique_constraint()`.

- [x] **Step 4: Execute alembic upgrade head and alembic check**

Run: `.\.venv\Scripts\python.exe -m alembic upgrade head` followed by `.\.venv\Scripts\python.exe -m alembic check` to verify zero schema drift.

- [x] **Step 5: Run migration test and verify pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/integration/test_postgres_migrations.py -ra`

---

### Task 2: Repository Fencing, Exponential Backoff & Dead-Letter Deduplication

**Files:**
- Modify: `src/zylar/persistence/repositories.py`
- Modify: `src/zylar/persistence/exceptions.py`
- Test: `tests/unit/test_checkpoint_repository.py`

**Interfaces:**
- Produces: `StaleLeaseError(PersistenceError)` in `exceptions.py`.
- In `CheckpointRepository`:
  - `acquire_lease(stream_id: str, worker_id: str, lease_seconds: int = 60) -> tuple[bool, int]` (returns `(acquired, lease_generation)`)
    - If `status == 'RETRYING'` and `next_retry_at > now`: returns `(False, 0)`.
    - Increments `lease_generation += 1` on acquisition.
  - `advance_checkpoint(stream_id: str, new_timestamp: datetime, last_id: str | None, processed_count: int, worker_id: str, lease_generation: int) -> None`
    - Verifies `lease_owner == worker_id` AND `lease_generation == expected_generation`. Raises `StaleLeaseError` if mismatched.
    - Resets `retry_count = 0`, `status = 'IDLE'`, `next_retry_at = None`, `last_error = None`.
  - `release_lease(stream_id: str, worker_id: str, lease_generation: int) -> bool`
    - Clears lease only if `lease_owner == worker_id and lease_generation == expected_generation`.
  - `record_failure(stream_id: str, error: str, max_retries: int, backoff_initial: float, backoff_factor: float, backoff_max: float) -> IngestionCheckpointModel`
    - Computes exponential backoff with jitter and sets `next_retry_at` and `lease_expires_at = next_retry_at`.
  - `quarantine_events(stream_id: str, dead_letters: list[dict[str, Any]]) -> int`
    - Upserts dead letters with `ON CONFLICT (stream_id, event_id) DO NOTHING`. Bounds payload size to 64KB.

- [x] **Step 1: Write unit tests for lease generation fencing and retry delay enforcement**

In `tests/unit/test_checkpoint_repository.py` and `tests/integration/test_postgres_checkpoints.py`:
- `test_acquire_lease_rejected_when_retrying_before_next_retry_at`
- `test_advance_checkpoint_rejects_stale_lease_generation`
- `test_record_failure_calculates_exponential_backoff_and_sets_next_retry_at`
- `test_quarantine_events_idempotent_deduplication`

- [x] **Step 2: Implement StaleLeaseError in exceptions.py**

Add `class StaleLeaseError(PersistenceError): pass` in `src/zylar/persistence/exceptions.py`.

- [x] **Step 3: Update CheckpointRepository in repositories.py**

Implement fencing token checks, retry interval enforcement, exponential backoff, and idempotent dead-letter upserts.

- [x] **Step 4: Run unit tests and verify pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_checkpoint_repository.py -ra`

---

### Task 3: Ingestion Worker Cursor Pagination & Atomic Transaction Boundary

**Files:**
- Modify: `agents/report_agent.py`
- Modify: `src/zylar/ingestion/engine.py`
- Test: `tests/unit/test_ingestion_worker.py`
- Test: `tests/integration/test_ingestion_checkpointing.py`

**Interfaces:**
- Consumes: `CheckpointRepository`, `UnitOfWork`, `Elasticsearch`.
- In `agents/report_agent.py`:
  - `generate_report_node(state: AgentState) -> dict[str, Any]`
  - If `state.get("defer_persistence")` is `True`, returns `{"incident_dto": incident_dto, "report": report_content, "contributing_ips": ..., "contributing_users": ...}` without committing its own UnitOfWork.
- In `CheckpointedIngestionWorker`:
  - `poll_and_process_batch() -> IngestionBatchResult`:
    - Queries Elasticsearch with `sort: [{"timestamp": {"order": "asc"}}, {"event_id.keyword": {"order": "asc", "unmapped_type": "keyword"}}]`.
    - If `watermark_id` is present, uses `search_after: [watermark_ts.isoformat(), watermark_id]`.
    - Executes workflow with `defer_persistence=True`.
    - Within a **single UnitOfWork**:
      1. `uow.persist_incident_lifecycle(state["incident_dto"], ...)` (if anomalies existed)
      2. `uow.checkpoints.advance_checkpoint(..., lease_generation=self.current_lease_generation)`
      3. `uow.checkpoints.release_lease(..., lease_generation=self.current_lease_generation)`
    - Both commit together atomically!

- [x] **Step 1: Write unit and integration tests for search_after pagination and atomic boundary**

In `tests/unit/test_ingestion_worker.py`:
- `test_worker_uses_search_after_with_compound_sort`
- `test_worker_handles_multi_page_equal_timestamps_without_stalling`
- `test_worker_aborts_on_stale_lease_generation`

In `tests/integration/test_ingestion_checkpointing.py`:
- `test_crash_before_commit_rolls_back_both_incident_and_checkpoint`
- `test_stale_worker_checkpoint_advance_rejected_by_lease_fencing`
- `test_worker_does_not_poll_before_next_retry_at`

- [x] **Step 2: Update generate_report_node in report_agent.py to support defer_persistence**

Allow the workflow to output validated `incident_dto` for external transaction coordination.

- [x] **Step 3: Update CheckpointedIngestionWorker in engine.py**

Implement `search_after`, pass `lease_generation`, coordinate single-transaction persistence, and sanitize `last_error` before storing.

- [x] **Step 4: Run worker unit and integration tests**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_ingestion_worker.py tests/integration/test_ingestion_checkpointing.py -ra`

---

### Task 4: Security Hardening (API, Sanitization, Compose, Dashboard)

**Files:**
- Modify: `elk_setup/docker-compose.yml`
- Modify: `src/zylar/core/security.py`
- Modify: `api/main.py`
- Modify: `dashboard/app.py`
- Modify: `src/zylar/core/settings.py`
- Modify: `.env.example`
- Test: `tests/api/test_security_sanitization.py`
- Test: `tests/unit/test_security.py`

**Interfaces:**
- Produces in `src/zylar/core/security.py`:
  - `sanitize_audit_details(data: Any, max_depth: int = 5, max_str_len: int = 1024) -> Any`
  - `LoginThrottler` class enforcing per-IP and per-account failed attempt limits.
- Produces in `dashboard/app.py`:
  - `escape_dot_identifier(val: str) -> str` escaping `\`, `"`, and newlines for Graphviz.
- In `api/main.py`:
  - `validation_exception_handler` scrubs raw `input` from 422 responses.
  - `/api/ingestion/status` masks raw exception traces from unauthorized clients and displays structured error codes.
  - `/api/auth/token` checks `LoginThrottler` to return 429 on abuse.

- [x] **Step 1: Write tests for audit sanitization, validation error scrubbing, and login throttling**

In `tests/unit/test_security.py`:
- Test `sanitize_audit_details` redacts passwords, tokens, API keys, URLs with user:pass.
- Test `LoginThrottler` locks out after threshold and recovers after window.

In `tests/api/test_security_sanitization.py`:
- Test 422 response does not echo sensitive input values.
- Test `/api/ingestion/status` does not leak raw exception text.

- [x] **Step 2: Update elk_setup/docker-compose.yml to bind localhost**

Change ports to `"127.0.0.1:9200:9200"` and `"127.0.0.1:5601:5601"`.

- [x] **Step 3: Implement sanitize_audit_details and LoginThrottler in security.py**

Implement recursive sanitization and rate limiting.

- [x] **Step 4: Update api/main.py error handlers, login throttling, and status endpoint**

Sanitize 422 details, apply login throttling to `/api/auth/token`, and sanitize `/api/ingestion/status`.

- [x] **Step 5: Update dashboard/app.py Graphviz escaping**

Sanitize DOT string node and edge identifiers.

- [x] **Step 6: Harmonize PostgreSQL configuration in settings.py and .env.example**

Standardize port `5434` and database `zylar_db` consistently across `.env.example` and `settings.py`.

- [x] **Step 7: Run security tests and verify pass**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_security.py tests/api/test_security_sanitization.py -ra`

---

### Task 5: Full Regression & Release Verification Checklist

**Files:**
- Run full regression suite across all units, APIs, and integrations.

- [x] **Step 1: Run complete pytest suite under ZYLAR_REQUIRE_POSTGRES=1**

Run: `powershell -Command "$env:ZYLAR_REQUIRE_POSTGRES = '1'; .\.venv\Scripts\python.exe -m pytest -ra"`
Expected: All tests pass with zero skips.

- [x] **Step 2: Run Alembic schema-drift check**

Run: `.\.venv\Scripts\python.exe -m alembic check`
Expected: `No new upgrade operations detected.`

- [x] **Step 3: Run Ruff and Mypy checks**

Run: `.\.venv\Scripts\python.exe -m ruff check src/ tests/ api/ dashboard/`
Run: `.\.venv\Scripts\python.exe -m mypy src/zylar/ingestion/ src/zylar/persistence/ src/zylar/core/`

- [x] **Step 4: Run Git diff check**

Run: `git diff --check`
Run: `git status --short`
