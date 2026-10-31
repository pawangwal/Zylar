# ADR-003: Bounded Ingestion Worker Runner with Monotonic Lease Fencing

## Context and Problem Statement

In early phases, background ingestion ran as an in-process thread pool or APScheduler job inside the FastAPI application process. This created several critical production risks:
1. **Fate Sharing**: A slow, CPU-bound ingestion batch or an unhandled crash in the worker process degraded or killed the user-facing FastAPI HTTP server.
2. **Double-Processing & Split-Brain**: Multiple worker replicas polling the same event stream could process overlapping batches, duplicate incidents, or commit out-of-order stream watermarks.
3. **Lease Coupling**: If worker process heartbeats and stream lease ownership were coupled into a single table or lock, transient network hiccups would invalidate stream processing or leave orphaned locks.

## Decision Drivers

- Isolate the background log ingestion runtime from the interactive REST API.
- Prevent duplicate processing and out-of-order watermark commits under multi-worker concurrency.
- Ensure graceful draining and bounded shutdown on container restart (`SIGTERM`).
- Decouple worker process health telemetry from stream lease ownership.

## Considered Options

1. **In-Process Scheduler (FastAPI lifespan)**: Retain APScheduler running in the same Python interpreter as FastAPI.
2. **External Distributed Queue (Celery / Redis / RabbitMQ)**: Deploy Celery with Redis for job queuing.
3. **Dedicated Dedicated Worker Process with PostgreSQL Optimistic Lease Fencing (Chosen)**: Run `python -m zylar.ingestion.runner` as an independent container process, coordinating stream ownership via PostgreSQL optimistic leases with monotonic fencing tokens (`lease_generation`).

## Decision Outcome

Chosen option: **Dedicated Worker Process with PostgreSQL Optimistic Lease Fencing (Option 3)**.

### Architectural Rules:
1. **Process Separation**: Ingestion runs in a dedicated container (`worker`), with its own process pool, database pool (`worker_db_pool_size`), and signal handlers.
2. **Heartbeat vs Lease Decoupling**:
   - `worker_instances`: Tracks process identity (`worker_instance_id`), hostname, status (`ACTIVE`, `DRAINING`, `STOPPED`), and periodic heartbeat (`last_heartbeat_at`).
   - `ingestion_checkpoints`: Tracks stream watermark (`last_processed_timestamp`, `last_processed_id`), `lease_owner`, `lease_expires_at`, and `lease_generation`.
3. **Optimistic Fencing Tokens**:
   - When acquiring or renewing a lease, `lease_generation` is monotonically incremented.
   - All checkpoint updates enforce conditional matching:
     ```sql
     UPDATE ingestion_checkpoints 
     SET ... 
     WHERE stream_id = :id AND lease_owner = :worker AND lease_generation = :expected_gen;
     ```
   - If zero rows are updated, the worker raises `FencedLeaseError` and aborts batch commit immediately.
4. **Graceful Draining**: On `SIGINT` or `SIGTERM`, the runner sets `_is_draining = True`, allows any active batch to complete strictly if the lease remains valid, updates `worker_instances.status = 'STOPPED'`, and closes database pools within 30 seconds.

### Consequences

#### Positive:
- Complete process isolation: Worker memory usage or crashes cannot impact API responsiveness.
- Zero split-brain or duplicate commits: Fencing tokens mathematically prevent stale workers from committing past an active leader.
- Decoupled observability: Worker exposes `/metrics` and `/healthz` directly on an internal port (9102).

#### Negative:
- Multi-container coordination: Requires managing separate container lifecycles in Docker Compose.

