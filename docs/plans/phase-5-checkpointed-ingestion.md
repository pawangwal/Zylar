# Phase 5 — Checkpointed Ingestion and Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ephemeral Elasticsearch timestamp-window polling with a persistent, replay-safe, and failure-resilient ingestion engine that tracks watermarks and lease state in PostgreSQL, isolates poison events, bounds retries, and never advances progress before durable persistence.

**Architecture:** A dedicated ingestion worker polls Elasticsearch using stable sort `(timestamp asc, _id asc)` from a persistent PostgreSQL watermark. If processing succeeds, the watermark advances atomically in the same transaction as incident/evidence persistence. If poison events occur, they are quarantined to a dead-letter queue without blocking the batch. Transient failures trigger bounded exponential backoff with jitter and circuit breaking.

**Tech Stack:** Python 3.12, SQLAlchemy 2.x, PostgreSQL 16, Alembic, Elasticsearch 8.x client, Tenacity / backoff logic, pytest.

**Spec:** Section 2 & 3 of user prompt (Phase 5 implementation scope & acceptance criteria) and Slice 6 of [`docs/zylar-implementation-plan.md`](file:///e:/ML%20Projects/Zylar/docs/zylar-implementation-plan.md).

## Global Constraints
- Target PostgreSQL database: port `5434`, `zylar_db`.
- Database uniqueness and transaction boundaries remain the concurrency and consistency authority.
- Do not advance a checkpoint before the corresponding data has been durably processed.
- No silent fallback or in-memory state bypass.
- Zero credential or raw secret exposure in logs or metrics.

---

### Task 1: Checkpoint & Dead-Letter Schema Migration

**Files:**
- Create: `alembic/versions/0002_checkpointed_ingestion.py`
- Modify: `src/zylar/persistence/models.py`
- Test: `tests/integration/test_postgres_migrations.py`

**Interfaces:**
- Produces: `IngestionCheckpointModel` (table `ingestion_checkpoints`), `DeadLetterEventModel` (table `dead_letter_events`).

- [x] **Step 1: Write migration test for revision 0002**
- [x] **Step 2: Add IngestionCheckpointModel and DeadLetterEventModel to models.py**
- [x] **Step 3: Create Alembic migration script 0002_checkpointed_ingestion.py**
- [x] **Step 4: Execute alembic upgrade head and alembic check**
- [x] **Step 5: Verify test passes**

---

### Task 2: Checkpoint & Dead-Letter Repository in Persistence Layer

**Files:**
- Modify: `src/zylar/persistence/repositories.py`
- Modify: `src/zylar/persistence/unit_of_work.py`
- Test: `tests/unit/test_checkpoint_repository.py`

**Interfaces:**
- Produces: `CheckpointRepository` with methods:
  - `get_or_create(stream_id: str, default_start_time: datetime) -> IngestionCheckpointModel`
  - `acquire_lease(stream_id: str, worker_id: str, lease_seconds: int = 60) -> bool`
  - `release_lease(stream_id: str, worker_id: str) -> None`
  - `advance_checkpoint(stream_id: str, new_timestamp: datetime, last_id: str | None, processed_count: int) -> None`
  - `record_failure(stream_id: str, error: str, max_retries: int = 5) -> IngestionCheckpointModel`
  - `quarantine_events(stream_id: str, dead_letters: list[dict[str, Any]]) -> None`
- Integrates: `uow.checkpoints` on `UnitOfWork`.

- [x] **Step 1: Write unit tests for CheckpointRepository leasing and watermark advancement**
- [x] **Step 2: Implement CheckpointRepository in repositories.py**
- [x] **Step 3: Expose checkpoints property in UnitOfWork**
- [x] **Step 4: Run unit tests and confirm pass**

---

### Task 3: Checkpointed Ingestion Worker Engine

**Files:**
- Create: `src/zylar/ingestion/__init__.py`
- Create: `src/zylar/ingestion/engine.py`
- Create: `src/zylar/ingestion/exceptions.py`
- Test: `tests/unit/test_ingestion_worker.py`

**Interfaces:**
- Consumes: `UnitOfWork`, `Elasticsearch`, `analyze_logs_node`, `detect_anomalies_node`, `build_workflow`.
- Produces: `CheckpointedIngestionWorker`:
  - `poll_and_process_batch() -> IngestionBatchResult`
  - Stable Elasticsearch querying `[{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}]`
  - Tie-breaker filtering for equal-timestamp records
  - Poison-event quarantine without blocking valid events
  - Exponential backoff on transient errors
  - Atomic transaction: incident persistence + watermark advancement

- [x] **Step 1: Write unit tests for IngestionWorker (resume watermark, tie-breaker, poison event, transient retry)**
- [x] **Step 2: Implement CheckpointedIngestionWorker and IngestionBatchResult**
- [x] **Step 3: Run unit tests and confirm pass**

---

### Task 4: Lifespan Integration & API Scheduler Replacement

**Files:**
- Modify: `api/main.py`
- Test: `tests/integration/test_api_workflow_boundary.py`

**Interfaces:**
- Replaces prototype `check_for_threats()` with `worker.poll_and_process_batch()` using the lifespan-managed `db_manager`.

- [x] **Step 1: Update api/main.py to wire CheckpointedIngestionWorker into lifespan**
- [x] **Step 2: Add health check reporting checkpoint lag and dead-letter count**
- [x] **Step 3: Run API tests and verify clean startup/shutdown**

---

### Task 5: Failure-Injection and Recovery Integration Verification

**Files:**
- Create: `tests/integration/test_ingestion_checkpointing.py`

**Scenarios:**
- Interruption between workflow execution and checkpoint advancement (rollback safety).
- Worker restart: resumes strictly from committed checkpoint.
- Replaying identical batches: zero duplicate incidents, zero duplicate recurrence counts.
- Elasticsearch connection outage: triggers backoff without crash or unmanaged connection leaks.
- Poison pill events: quarantined to `dead_letter_events`, batch proceeds.
- Concurrency test: multiple worker instances attempting lease acquisition; exactly one executes.

- [x] **Step 1: Write integration tests covering all 6 failure-injection scenarios**
- [x] **Step 2: Run with $env:ZYLAR_REQUIRE_POSTGRES = "1"**
- [x] **Step 3: Verify all tests pass with zero skips**
