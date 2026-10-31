# ADR-006: Distributed Observability, Prometheus Dual-Scrape, and Metric Ownership

## Context and Problem Statement

When operating decoupled services (an interactive FastAPI HTTP server and a background ingestion worker), metrics collection easily suffers from architectural anti-patterns:
1. **Shared In-Memory State**: If multiple processes attempt to write metrics to a shared file or SQLite database, lock contention and race conditions corrupt telemetry.
2. **Cardinality Explosions**: Labeling Prometheus metrics with high-cardinality values (e.g. `event_id`, `user_id`, or `source_ip`) causes Prometheus memory consumption to spike catastrophically.
3. **Commit-Boundary Inaccuracies**: Incrementing processed-event counters before a database transaction commits produces misleading operational dashboards that claim events were processed when the transaction actually rolled back.

## Decision Drivers

- Process-local metric ownership: Each runtime process must own and serve its own in-memory Prometheus metrics without cross-process locking.
- Strict low-cardinality label enforcement.
- Commit-boundary metric semantics: Counters representing durable work must only increment upon successful transaction commit.
- Seamless Prometheus scraping across both API and Worker containers.

## Considered Options

1. **Centralized StatsD / Redis Daemon**: Route all process metrics over UDP to a local StatsD exporter.
2. **Prometheus Multiprocess Mode (filesystem mmap)**: Use `prometheus_client` directory-based shared memory files.
3. **Dedicated Process-Local Scrape Endpoints with Prometheus Dual-Scrape Configuration (Chosen)**:
   - FastAPI serves its local metrics on `:8000/api/metrics` (and `/metrics`).
   - Worker serves its local metrics on an internal HTTP server at `:9102/metrics`.
   - Prometheus scrapes both targets independently, combining them into unified service-labeled metrics.

## Decision Outcome

Chosen option: **Dedicated Process-Local Scrape Endpoints (Option 3)**.

### Architectural Rules:
1. **Endpoint Segregation**:
   - `api:8000`: Scraped by Prometheus as job `zylar-api` with label `service: "zylar-api"`.
   - `worker:9102`: Scraped by Prometheus as job `zylar-worker` with label `service: "zylar-worker"`.
2. **Commit-Boundary Counters**:
   - `zylar_workflow_events_completed_total`: Increments when the API workflow pipeline completes successfully.
   - `zylar_incidents_persisted_total`: Increments strictly upon successful PostgreSQL incident transaction commit.
   - `zylar_ingestion_checkpoint_advances_total`: Increments strictly upon successful stream checkpoint watermark commit.
3. **Low-Cardinality Enforcement**: Metric labels are strictly restricted to bounded enums: `status` (`success`, `failed`), `rule` (known detection rule IDs), and `le` (histogram bucket boundaries). High-cardinality entities are strictly forbidden in metric labels.
4. **Truthful UI Meters**: In `dashboard/app.py`, metric readings return `status: "unavailable"` if Prometheus or backend endpoints cannot be reached, preventing misleading zero-value readings during outages.

### Consequences

#### Positive:
- Zero cross-process lock contention: Metrics operations execute in nanoseconds using Python process-local in-memory locks.
- Clean Prometheus integration: Standard scraping with service labeling allows granular monitoring of API versus Worker throughput and latency.
- Accurate operational state: Metrics accurately reflect durable PostgreSQL commits rather than speculative attempts.

#### Negative:
- Port allocation: Worker container runs an internal lightweight Python HTTP server on port 9102.

