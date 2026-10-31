# Zylar System Architecture

## 1. Executive Architecture Overview

Zylar is an enterprise-grade autonomous Security Operations Center (SOC) platform implemented as a **modular monolith**. It combines deterministic attack pattern detection, stateful entity correlation, mathematical risk scoring, and optional local LLM semantic summarization to investigate, score, and mitigate security threats in real time.

```mermaid
flowchart TD
    subgraph IngestionBoundary["Ingestion & Boundary Tier"]
        RawEvents["Raw Security Logs (Syslog, Auth, NetFlow)"]
        ES[("Elasticsearch 8.x\n(Raw Event Search Engine)")]
    end

    subgraph ComputeTier["Runtime Processing Tier"]
        Worker["Autonomous Ingestion Worker\n(zylar.ingestion.runner)\n- Lease Fencing\n- Deduplication\n- Dead-Letter Queue"]
        API["FastAPI Interactive Backend\n(:8000)\n- RBAC & JWT Auth\n- Threat Graph Endpoint\n- Synchronous Workflows"]
        UI["Streamlit SOC Dashboard\n(:8501)\n- Real-time KPI Meters\n- Incident Timeline\n- Centrality Graph Visualizer"]
    end

    subgraph IntelligenceTier["Analysis & Intelligence Engines"]
        Rules["Deterministic Detection Rules\n(Brute Force, Port Scan, Ransomware)"]
        RiskEngine["Mathematical Risk Policy Engine\n(5 Normalized Factors: [0-100])"]
        GraphEngine["Typed Correlation Graph Service\n(NetworkX Centrality Scoring)"]
        LLM["Optional Local LLM (Ollama)\n(Circuit-Breaker Bounded: <= 5.0s)"]
    end

    subgraph StorageTier["Authoritative Storage & Observability"]
        PG[("PostgreSQL 16.x\n(Authoritative Operational Store)\n- Incidents & Mitigations\n- Stream Checkpoints & Leases\n- Worker Heartbeats\n- Audit Logs & Users")]
        Prometheus["Prometheus Server\n(:9090 Dual-Scrape)\n- API (:8000/api/metrics)\n- Worker (:9102/metrics)"]
    end

    RawEvents --> ES
    ES -->|Watermark Polling| Worker
    Worker --> Rules
    Worker --> RiskEngine
    Worker --> GraphEngine
    Worker -.->|Optional Enrichment| LLM
    Worker -->|ACID Commit| PG
    Worker -->|Prometheus Metrics| Prometheus

    UI -->|REST Queries| API
    API -->|Read Incidents & Status| PG
    API -->|Search Raw Logs| ES
    API -->|Prometheus Metrics| Prometheus
```

---

## 2. Core Subsystems & Contracts

### 2.1 Dual-Storage Persistence Architecture
- **PostgreSQL 16 (System of Record)**: Authoritative store for security incidents, entity correlation history, stream checkpoints, leases, worker instance heartbeats, dead-letter events, user credentials, and audit logs.
- **Elasticsearch 8 (Search Engine)**: Dedicated distributed search engine storing append-only raw security event logs (`security-events-*`).

### 2.2 Process & Network Boundary Separation
- **`api` Container**: Published on loopback `127.0.0.1:8000`. Runs FastAPI with `enable_ingestion_scheduler=false` (zero background polling).
- **`worker` Container**: Internal network only. No published host ports. Executes `python -m zylar.ingestion.runner`. Serves internal metrics on port `9102`.
- **`dashboard` Container**: Published on loopback `127.0.0.1:8501`. Queries API for metrics, incident history, and worker telemetry.
- **`migration` Container**: One-shot container executing `alembic upgrade head` under `zylar_migration` administrative credentials before API or worker start.

### 2.3 Lease Fencing & Ingestion Sequence

```mermaid
sequenceDiagram
    autonumber
    participant W as Ingestion Worker
    participant ES as Elasticsearch
    participant PG as PostgreSQL (Checkpoints)
    participant Core as Analytics Engine

    W->>PG: Acquire lease with monotonic fencing token (lease_generation)
    alt Lease Acquired
        PG-->>W: Lease Granted (Generation G)
        W->>PG: Query committed watermark (last_ts, last_id)
        PG-->>W: Committed Watermark
        W->>ES: Query events range (gte: last_ts) sorted asc
        ES-->>W: Raw Event Hits
        W->>Core: Deduplicate against watermark boundary & evaluate rules
        Core-->>W: Valid Batch & Incident DTO
        W->>PG: BEGIN TRANSACTION
        W->>PG: Insert incident & audit logs
        W->>PG: Advance watermark (WHERE lease_generation = G)
        W->>PG: Release lease & COMMIT
        PG-->>W: Commit Acknowledged
    else Lease Contended / Generation Mismatch
        PG-->>W: Lease Busy / FencedLeaseError
        W->>W: Exponential backoff with jitter
    end
```

---

## 3. Database Least-Privilege Architecture

```mermaid
flowchart LR
    subgraph Roles["PostgreSQL Role Segregation"]
        MigRole["zylar_migration\n(Owner Role)"]
        AppRole["zylar_app\n(Runtime DML)"]
        ReadRole["zylar_read\n(Audit Read-Only)"]
    end

    subgraph Tables["Public Schema Objects"]
        Users["public.users\n(Column-restricted INSERT/UPDATE)"]
        Incidents["public.incidents\n(DML SELECT/INSERT/UPDATE)"]
        Checkpoints["public.ingestion_checkpoints\n(DML SELECT/INSERT/UPDATE)"]
        AuditLogs["public.audit_logs\n(Append-Only: SELECT/INSERT)"]
        Sequences["public.*_seq\n(USAGE only)"]
    end

    MigRole -->|Owns Schema & DDL| Tables
    AppRole -->|Table-Specific DML| Incidents
    AppRole -->|Table-Specific DML| Checkpoints
    AppRole -->|Strictly Append-Only| AuditLogs
    AppRole -->|No Role Escalation| Users
    AppRole -->|USAGE Only| Sequences
    ReadRole -->|SELECT Only| Incidents
    ReadRole -->|SELECT Only| AuditLogs
```

---

## 4. Observability & Metric Ownership

1. **API Process Metrics**: Served on `:8000/api/metrics` (and `/metrics`), reporting HTTP request latencies and workflow durations.
2. **Worker Process Metrics**: Served on internal port `:9102/metrics`, reporting poll cycle latencies, events received, events deduplicated, dead letters quarantined, and checkpoint advances.
3. **Commit-Boundary Counters**:
   - `zylar_workflow_events_completed_total`: Incremented upon workflow execution completion.
   - `zylar_incidents_persisted_total`: Incremented strictly upon successful PostgreSQL incident commit.
   - `zylar_ingestion_checkpoint_advances_total`: Incremented strictly upon successful checkpoint advancement.

