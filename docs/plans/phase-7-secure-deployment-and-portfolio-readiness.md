# Phase 7: Secure Deployment, Operational Resilience & Portfolio Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform Zylar into a production-hardened, self-healing, auditable, and portfolio-ready autonomous SOC platform. Delivers multi-service container orchestration with strict process separation between the API and autonomous worker, confirmed Elasticsearch 8.x client compatibility, least-privilege PostgreSQL role segregation, durable identity and worker heartbeat persistence, automated backup/restore verification drills, actionable analyst incident runbooks, Architectural Decision Records (ADRs), and a reproducible non-destructive portfolio demonstration script.

**Architecture:**
- **Modular Monolith Runtime Process Separation:** The application codebase (`zylar.*`) remains a unified Python package, but runtime execution is split across distinct containers:
  - `api`: FastAPI application with `ZYLAR_ENABLE_INGESTION_SCHEDULER=false` (serves HTTP requests, health probes, Prometheus API metrics, and threat graph; does NOT run background ingestion polling).
  - `worker`: Dedicated autonomous worker process executing `python -m zylar.ingestion.runner` with `ZYLAR_ENABLE_INGESTION_SCHEDULER=true` (owns stream polling, monotonic lease fencing, PostgreSQL heartbeat updates, and exposes internal Prometheus worker metrics on port `9102`; does NOT run Uvicorn/FastAPI).
  - `migration`: One-shot migration container running Alembic under privileged role `zylar_migration`. Runs to completion before `api` or `worker` start (`condition: service_completed_successfully`).
  - `dashboard`: Streamlit analyst interface consuming API telemetry and PostgreSQL-backed operational status.
  - `postgres`: PostgreSQL 16 database with persistent storage volume `postgres_data`. Authoritative system of record for incidents, checkpoints, leases, audit logs, DLQ, user identities, and worker heartbeats.
  - `elasticsearch`: Elasticsearch 8.x log search cluster with persistent storage volume `es_data`. Specialized search engine for raw security events.
  - `kibana`: Log exploration interface (managed under optional Compose profile `monitoring`).
  - `simulator`: Profile-driven attack generator (managed under optional Compose profile `sim`).
- **Data Ownership Invariants:**
  - Raw security telemetry: Elasticsearch.
  - Authoritative operational state (incidents, audit trails, risk history, checkpoints, leases, users, heartbeats): PostgreSQL.
  - Ephemeral operational metrics: Prometheus (scraped independently from API `:8000/metrics` and Worker `:9102/metrics`).
- **PostgreSQL 3-Role Least-Privilege & Ownership Model:**
  - `zylar_migration`: DDL owner role. Owns schema `public` and all database objects. Used exclusively by Alembic during migrations.
  - `zylar_app`: Runtime DML-only role. Table-specific permissions:
    - `audit_logs`: `INSERT`, `SELECT` only. Strictly NO `UPDATE`, NO `DELETE` (append-only audit trail).
    - `incidents`: `SELECT`, `INSERT`, `UPDATE` (scoped lifecycle transitions). Strictly NO `DELETE`.
    - `incident_events`: `SELECT`, `INSERT` (association records). Strictly NO `UPDATE`, NO `DELETE`.
    - `offender_ip_history`, `offender_user_history`: `SELECT`, `INSERT`, `UPDATE`. Strictly NO `DELETE`.
    - `ingestion_checkpoints`: `SELECT`, `INSERT`, `UPDATE` (lease fencing and watermark updates). Strictly NO `DELETE`.
    - `dead_letter_events`: `SELECT`, `INSERT`, `UPDATE` (triage status updates). Strictly NO `DELETE`.
    - `users`: `SELECT`, `INSERT`, `UPDATE` (profile updates; role changes restricted). Strictly NO `DELETE`.
    - `worker_instances`: `SELECT`, `INSERT`, `UPDATE`. Strictly NO `DELETE`.
    - Sequences: `USAGE` on sequences (for `nextval`). Strictly NO `UPDATE` (`setval`) to runtime roles.
    - Schema: `USAGE` on schema `public`. Strictly denied `CREATE` on schema `public`. Cannot execute `DROP`, `ALTER`, or `TRUNCATE` because it owns no objects.
  - `zylar_read`: Read-only audit role (`SELECT` only on authorized tables).
- **Durable Identity & Concurrency-Safe Bootstrap:**
  - Users and password hashes are persisted in PostgreSQL (`users` table). No in-memory identity store in production (fails closed if database unavailable).
  - Concurrency-safe administrator bootstrap via transactional advisory lock (`pg_advisory_xact_lock`) preventing race conditions during multi-instance startup.
- **Worker Heartbeat vs. Lease Fencing:**
  - Worker process liveness (`worker_instances.last_heartbeat_at`) indicates container health; checkpoint lease validity (`ingestion_checkpoints.lease_token` and `lease_generation`) indicates transaction processing ownership. A live heartbeat NEVER grants processing authority without a valid lease.
  - Conditional checkpoint commits: `UPDATE ingestion_checkpoints SET ... WHERE stream_id = :id AND lease_token = :token AND lease_generation = :gen`. Fails closed if fenced.

**Tech Stack:** Docker Compose v2, Python 3.12, PostgreSQL 16.8, Elasticsearch 8.17, Kibana 8.17, FastAPI, Streamlit, NetworkX, scikit-learn, pytest, Ruff, Mypy.

**Spec Reference:** `docs/zylar-implementation-plan.md` (Slice 8: Secure deployment, recovery and portfolio evidence).

---

## Global Constraints & Security Invariants

1. **Process Separation:** The API service and Ingestion Worker MUST NOT run duplicate polling schedulers. The API process serves client requests with `ZYLAR_ENABLE_INGESTION_SCHEDULER=false`, while the Worker container process owns stream polling with `ZYLAR_ENABLE_INGESTION_SCHEDULER=true` via dedicated runner `python -m zylar.ingestion.runner`.
2. **Localhost Port Isolation:** All published container ports (`8000`, `8501`, `5432`, `9200`, `5601`) MUST bind strictly to `127.0.0.1` by default to prevent accidental exposure of telemetry, incidents, or credentials over public network interfaces.
3. **Table-Specific Least Privilege:** Runtime application connections (`zylar_app`) MUST NOT possess blanket DML on all tables. Specifically, `audit_logs` must be append-only (`INSERT`, `SELECT` only). Sequences must be limited to `USAGE`. Schema migrations must execute strictly under `zylar_migration`.
4. **Non-Root Containers:** All custom container images MUST create and execute under non-privileged system user `zylaruser` (UID 10001, GID 10001).
5. **No Hardcoded Secrets & Fail-Closed TLS:** All credentials, tokens, and database passwords MUST be injected via environment variables or Docker secrets. In production mode (`environment == "production"`), the system must reject unauthenticated Elasticsearch connections, require HTTPS, enforce certificate verification, and fail closed if credentials or certificates are invalid.
6. **Separation of Heartbeat and Lease:** Worker process liveness (`worker_instances.last_heartbeat_at`) indicates container health; checkpoint lease validity (`ingestion_checkpoints.lease_token` and `lease_generation`) indicates transaction processing ownership. A live heartbeat NEVER grants processing authority without a valid lease.
7. **Semantic Backup Parity vs PITR Targets:** Logical backups must demonstrate semantic parity across schemas, row counts, sequence states, and data integrity smoke tests. Point-in-Time Recovery (PITR) RPO ($\le 5\text{m}$) and RTO ($\le 30\text{m}$) are documented as operational targets to be verified through timed recovery drills.
8. **Isolated Demo Scenarios:** The demonstration scenario MUST generate unique execution run IDs (`demo_run_id`), use dedicated test streams and test Elasticsearch indices, operate in non-destructive modes, and strictly refuse execution against production databases. Dry-run mode (`dry_run=True`) must perform zero persistent writes.

---

### Phase 7 Execution Roadmap

| Stage | Focus Area | Key Deliverables |
|---|---|---|
| **Phase 7.0** | Security & Deployment Contracts | Settings validation, fail-closed ES TLS/auth, aggregate DB pool budgets, request limits |
| **Phase 7.1** | PostgreSQL Ownership, Roles & Durable Identity | Object ownership transfer, table-specific permissions, concurrency-safe user bootstrap |
| **Phase 7.2** | Dedicated Worker Runner & Lifecycle Contracts | `zylar.ingestion.runner`, heartbeat thread, lease fencing, graceful draining, status API |
| **Phase 7.3** | Detection Rule & Correlation Hardening | Stateful ransomware window semantics, calibrated confidence parameters, bounded graph inputs |
| **Phase 7.4** | Multi-Service Container Orchestration | `compose.yaml`, one-shot migration job, non-root Dockerfiles, secret mounts, health dependencies |
| **Phase 7.5** | Distributed Observability & Metric Ownership | Dual-scrape Prometheus config, commit-boundary counter semantics, Streamlit health cards |
| **Phase 7.6** | Backup & Recovery Verification Drill | Semantic parity backup drill, sequence verification, ES recovery strategy, target RPO/RTO |
| **Phase 7.7** | Operational Runbooks & ADRs | 6 operational playbooks, ADR-001 through ADR-006 (provider-isolated LLM) |
| **Phase 7.8** | Portfolio Evidence & Verification Gate | Non-destructive demo with dry-run separation, threat model, failure injection tests, CI pass |

---

### Task 7.0: Security, Identity & Deployment Contracts

**Files:**
- Modify: `src/zylar/core/settings.py`
- Modify: `.env.example`
- Create: `tests/unit/test_phase7_settings_contracts.py`

**Interfaces:**
- Consumes: Existing `Settings` in `src/zylar/core/settings.py`.
- Produces: Hardened configuration attributes: `elasticsearch_ca_certs: str | None`, `elasticsearch_api_key: SecretStr | None`, `api_db_pool_size: int`, `api_db_max_overflow: int`, `worker_db_pool_size: int`, `worker_db_max_overflow: int`, `max_workflow_concurrency: int`, strict fail-closed production validation.

- [ ] **Step 1: Write failing test for configuration contracts and aggregate connection budgeting**

```python
# tests/unit/test_phase7_settings_contracts.py
import pytest
from pydantic import ValidationError
from pydantic_core import SecretStr
from zylar.core.settings import Settings

def test_production_elasticsearch_requires_credentials_and_https():
    """Production mode must reject Elasticsearch URLs using HTTP or missing authentication."""
    # Missing password / API key on HTTPS
    with pytest.raises(ValidationError, match="ZYLAR_ELASTICSEARCH_PASSWORD or ZYLAR_ELASTICSEARCH_API_KEY"):
        Settings(
            environment="production",
            auth_signing_key=SecretStr("a-very-long-production-signing-key-32-chars-minimum"),
            bootstrap_admin_password=SecretStr("a-strong-admin-password-1234"),
            database_url="postgresql+psycopg://zylar_app:strong-app-pwd-123@127.0.0.1:5432/zylar_db",
            elasticsearch_url="https://elasticsearch:9200",
            elasticsearch_password=None,
            elasticsearch_api_key=None,
        )

    # Insecure HTTP in production
    with pytest.raises(ValidationError, match="https://"):
        Settings(
            environment="production",
            auth_signing_key=SecretStr("a-very-long-production-signing-key-32-chars-minimum"),
            bootstrap_admin_password=SecretStr("a-strong-admin-password-1234"),
            database_url="postgresql+psycopg://zylar_app:strong-app-pwd-123@127.0.0.1:5432/zylar_db",
            elasticsearch_url="http://elasticsearch:9200",
            elasticsearch_password=SecretStr("strong-es-password-1234"),
        )

def test_elasticsearch_client_kwargs_supports_api_key_and_ca_certs():
    """Settings must propagate api_key and ca_certs into elasticsearch_client_kwargs."""
    s = Settings(
        elasticsearch_url="https://127.0.0.1:9200",
        elasticsearch_ca_certs="/run/secrets/es_ca.crt",
        elasticsearch_api_key=SecretStr("test-api-key-value"),
    )
    kwargs = s.elasticsearch_client_kwargs
    assert kwargs.get("ca_certs") == "/run/secrets/es_ca.crt"
    assert kwargs.get("verify_certs") is True
    assert kwargs.get("api_key") == "test-api-key-value"
    assert "basic_auth" not in kwargs

def test_aggregate_database_connection_pool_budget():
    """Total maximum connections across API and Worker must not exceed planned capacity limit (50)."""
    s = Settings()
    # Formula: N_api * (pool + overflow) + N_worker * (pool + overflow) + C_other
    max_api_conns = s.api_db_pool_size + s.api_db_max_overflow
    max_worker_conns = s.worker_db_pool_size + s.worker_db_max_overflow
    total_budget = max_api_conns + max_worker_conns + 5  # 5 reserved for migrations/admin
    assert total_budget <= 50, f"Total database connection budget {total_budget} exceeds safe headroom limit of 50"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_phase7_settings_contracts.py -v`
Expected: FAIL with missing fields or validation errors.

- [ ] **Step 3: Implement settings contracts and production validation**

In `src/zylar/core/settings.py`:
- Add `elasticsearch_ca_certs: str | None = Field(default=None, description="Path to trusted CA certificate bundle for Elasticsearch TLS")`.
- Add `elasticsearch_api_key: SecretStr | None = Field(default=None, description="Elasticsearch API key credential")`.
- Add `api_db_pool_size: PositiveInt = Field(default=10, description="SQLAlchemy pool size for API process")`.
- Add `api_db_max_overflow: int = Field(default=10, ge=0, description="SQLAlchemy max overflow for API process")`.
- Add `worker_db_pool_size: PositiveInt = Field(default=5, description="SQLAlchemy pool size for Worker process")`.
- Add `worker_db_max_overflow: int = Field(default=5, ge=0, description="SQLAlchemy max overflow for Worker process")`.
- Add `max_workflow_concurrency: PositiveInt = Field(default=5, description="Maximum concurrent LangGraph workflow runs in API process")`.
- In `elasticsearch_client_kwargs`:
  ```python
  if self.elasticsearch_ca_certs:
      kwargs["ca_certs"] = self.elasticsearch_ca_certs
  if self.elasticsearch_api_key:
      kwargs["api_key"] = self.elasticsearch_api_key.get_secret_value()
  elif self.elasticsearch_password:
      username = self.elasticsearch_username or parsed.username or "elastic"
      kwargs["basic_auth"] = (username, self.elasticsearch_password.get_secret_value())
  ```
- In `validate_production_secrets()`:
  - If `environment == "production"`, assert `str(self.elasticsearch_url).lower().startswith("https://")`.
  - If `environment == "production"`, assert `(self.elasticsearch_password is not None) or (self.elasticsearch_api_key is not None)`.
  - Assert that `(self.api_db_pool_size + self.api_db_max_overflow + self.worker_db_pool_size + self.worker_db_max_overflow + 5) <= 50`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_phase7_settings_contracts.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/zylar/core/settings.py tests/unit/test_phase7_settings_contracts.py .env.example
git commit -m "feat(settings): enforce fail-closed production ES TLS, auth, and connection budgets"
```

---

### Task 7.1: PostgreSQL Ownership, Roles & Durable Identity

**Files:**
- Create: `alembic/versions/20261030_0001_phase7_durable_identity_and_worker_heartbeats.py`
- Modify: `src/zylar/persistence/models.py`
- Modify: `src/zylar/persistence/repositories.py`
- Modify: `src/zylar/core/security.py`
- Create: `scripts/sql/00_init_roles.sql`
- Create: `scripts/setup_postgres_roles.py`
- Create: `tests/unit/test_durable_identity.py`
- Create: `tests/integration/test_postgres_role_privileges.py`

**Interfaces:**
- Consumes: SQLAlchemy `Base` from `src/zylar/persistence/models.py`, `UnitOfWork` from `src/zylar/persistence/unit_of_work.py`.
- Produces: `UserModel`, `WorkerInstanceModel`, `UserRepository`, `WorkerInstanceRepository`, Table-specific PostgreSQL privilege script with ownership transfer, PostgreSQL-backed `UserStore` with concurrency-safe advisory lock bootstrap.

- [ ] **Step 1: Write failing test for durable identity and worker heartbeat models**

```python
# tests/unit/test_durable_identity.py
import uuid
import pytest
from datetime import UTC, datetime
from zylar.core.security import Role, UserPrincipal, hash_password, verify_password
from zylar.persistence.models import UserModel, WorkerInstanceModel

def test_user_model_instantiation():
    """UserModel must enforce UUID primary key, unique username, and role constraints."""
    user_id = uuid.uuid4()
    user = UserModel(
        id=user_id,
        username="analyst_bob",
        hashed_password=hash_password("SuperSecret123!"),
        role="analyst",
        disabled=False,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    assert user.id == user_id
    assert user.username == "analyst_bob"
    assert verify_password("SuperSecret123!", user.hashed_password)

def test_worker_instance_model_decoupled_from_stream_leases():
    """WorkerInstanceModel records process liveness only; stream leases reside on checkpoints."""
    instance_id = str(uuid.uuid4())
    worker = WorkerInstanceModel(
        worker_instance_id=instance_id,
        worker_name="worker-primary",
        hostname="zylar-worker-prod-1",
        started_at=datetime.now(UTC),
        last_heartbeat_at=datetime.now(UTC),
        status="RUNNING",
    )
    assert worker.worker_instance_id == instance_id
    assert not hasattr(worker, "lease_generation"), "lease_generation must not reside on worker_instances"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_durable_identity.py -v`
Expected: FAIL with `ImportError: cannot import name 'UserModel'`.

- [ ] **Step 3: Implement Alembic migration, SQLAlchemy models, and table-specific permissions**

1. Create migration `alembic/versions/20261030_0001_phase7_durable_identity_and_worker_heartbeats.py`:
   - Table `users`:
     - `id`: `sa.UUID(as_uuid=True)`, primary_key=True
     - `username`: `sa.String(128)`, unique=True, nullable=False
     - `hashed_password`: `sa.String(255)`, nullable=False
     - `role`: `sa.String(32)`, nullable=False
     - `disabled`: `sa.Boolean()`, nullable=False, server_default=sa.text("false")
     - `created_at`: `sa.DateTime(timezone=True)`, nullable=False
     - `updated_at`: `sa.DateTime(timezone=True)`, nullable=False
   - Table `worker_instances`:
     - `worker_instance_id`: `sa.String(128)`, primary_key=True
     - `worker_name`: `sa.String(128)`, nullable=False
     - `hostname`: `sa.String(255)`, nullable=False
     - `started_at`: `sa.DateTime(timezone=True)`, nullable=False
     - `last_heartbeat_at`: `sa.DateTime(timezone=True)`, nullable=False
     - `last_successful_cycle_at`: `sa.DateTime(timezone=True)`, nullable=True
     - `last_failed_cycle_at`: `sa.DateTime(timezone=True)`, nullable=True
     - `status`: `sa.String(32)`, nullable=False
     - `last_error_code`: `sa.String(64)`, nullable=True
2. Define models in `src/zylar/persistence/models.py`.
3. Add `UserRepository` and `WorkerInstanceRepository` in `src/zylar/persistence/repositories.py`.
4. Refactor `UserStore` in `src/zylar/core/security.py`:
   - Requires SQLAlchemy `session_factory`. In production mode (`environment == "production"`), raise `RuntimeError` if `session_factory` is None (fail closed; zero in-memory fallback).
   - In `_bootstrap_admin()`: Use PostgreSQL transactional advisory lock (`SELECT pg_advisory_xact_lock(742109)`) before checking if `users` table is empty. Insert initial admin atomically (`INSERT ... ON CONFLICT (username) DO NOTHING`).
5. Create `scripts/sql/00_init_roles.sql`:
   ```sql
   -- Idempotent role creation
   DO $$ BEGIN
     IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_migration') THEN
       CREATE ROLE zylar_migration WITH LOGIN PASSWORD 'migration_password';
     END IF;
     IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_app') THEN
       CREATE ROLE zylar_app WITH LOGIN PASSWORD 'app_password';
     END IF;
     IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_read') THEN
       CREATE ROLE zylar_read WITH LOGIN PASSWORD 'read_password';
     END IF;
   END $$;

   -- 1. Migration administrative owner role
   GRANT CONNECT ON DATABASE zylar_db TO zylar_migration;
   ALTER SCHEMA public OWNER TO zylar_migration;

   -- Transfer ownership of all existing objects to zylar_migration
   DO $$
   DECLARE
     r RECORD;
   BEGIN
     FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
       EXECUTE 'ALTER TABLE public.' || quote_ident(r.tablename) || ' OWNER TO zylar_migration';
     END LOOP;
     FOR r IN (SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public') LOOP
       EXECUTE 'ALTER SEQUENCE public.' || quote_ident(r.sequence_name) || ' OWNER TO zylar_migration';
     END LOOP;
   END $$;

   -- 2. Runtime application role (Table-specific permissions)
   GRANT CONNECT ON DATABASE zylar_db TO zylar_app;
   GRANT USAGE ON SCHEMA public TO zylar_app;

   -- Append-only audit logs: NO UPDATE, NO DELETE
   GRANT SELECT, INSERT ON TABLE public.audit_logs TO zylar_app;

   -- Operational tables: SELECT, INSERT, UPDATE; NO DELETE
   GRANT SELECT, INSERT, UPDATE ON TABLE public.incidents TO zylar_app;
   GRANT SELECT, INSERT ON TABLE public.incident_events TO zylar_app;
   GRANT SELECT, INSERT, UPDATE ON TABLE public.offender_ip_history TO zylar_app;
   GRANT SELECT, INSERT, UPDATE ON TABLE public.offender_user_history TO zylar_app;
   GRANT SELECT, INSERT, UPDATE ON TABLE public.ingestion_checkpoints TO zylar_app;
   GRANT SELECT, INSERT, UPDATE ON TABLE public.dead_letter_events TO zylar_app;
   GRANT SELECT, INSERT, UPDATE ON TABLE public.users TO zylar_app;
   GRANT SELECT, INSERT, UPDATE ON TABLE public.worker_instances TO zylar_app;

   -- Sequence usage for nextval; NO UPDATE (setval) to prevent sequence manipulation
   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO zylar_app;

   -- Revoke DDL creation and truncation
   REVOKE ALL ON SCHEMA public FROM PUBLIC;
   REVOKE CREATE ON SCHEMA public FROM zylar_app;
   REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM zylar_app;

   -- 3. Read-only audit role
   GRANT CONNECT ON DATABASE zylar_db TO zylar_read;
   GRANT USAGE ON SCHEMA public TO zylar_read;
   GRANT SELECT ON ALL TABLES IN SCHEMA public TO zylar_read;
   ```
6. Create runner `scripts/setup_postgres_roles.py` that connects via administrative credentials, reads passwords securely from environment variables, and executes the ownership transfer and grants.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_durable_identity.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add alembic/versions/ src/zylar/persistence/ src/zylar/core/security.py scripts/sql/00_init_roles.sql scripts/setup_postgres_roles.py tests/unit/test_durable_identity.py
git commit -m "feat(persistence): implement durable identity with advisory-locked bootstrap and table-specific permissions"
```

---

### Task 7.2: Dedicated Worker Runner & Lifecycle Contracts

**Files:**
- Create: `src/zylar/ingestion/runner.py`
- Modify: `src/zylar/ingestion/engine.py`
- Modify: `api/main.py`
- Create: `tests/unit/test_worker_runner.py`
- Create: `tests/integration/test_worker_lifecycle_fencing.py`

**Interfaces:**
- Consumes: `CheckpointedIngestionWorker` from `src/zylar/ingestion/engine.py`, `WorkerInstanceRepository` from `src/zylar/persistence/repositories.py`.
- Produces: Executable CLI `python -m zylar.ingestion.runner` with unique `worker_instance_id`, independent heartbeat thread using separate DB sessions and `func.now()`, lease fencing checks before batch commit, graceful draining on `SIGINT`/`SIGTERM`, and internal metrics server on port `9102`.

- [ ] **Step 1: Write failing test for worker runner lifecycle, heartbeat, and lease fencing**

```python
# tests/unit/test_worker_runner.py
import pytest
from unittest.mock import MagicMock, patch
from zylar.ingestion.runner import IngestionRunner

def test_runner_initialization_generates_unique_instance_id():
    """Each runner process must generate a unique UUID instance ID separate from worker name."""
    r1 = IngestionRunner(worker_name="worker-a")
    r2 = IngestionRunner(worker_name="worker-a")
    assert r1.worker_instance_id != r2.worker_instance_id
    assert r1.worker_name == "worker-a"

def test_runner_draining_rejects_new_cycles_and_cancels_fenced_batch():
    """When DRAINING or lease lost, worker must abort active batch without committing checkpoint."""
    runner = IngestionRunner(worker_name="worker-test")
    runner._is_draining = True
    assert runner.should_continue_polling() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_worker_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'zylar.ingestion.runner'`.

- [ ] **Step 3: Implement dedicated worker runner and database status queries**

1. Create `src/zylar/ingestion/runner.py`:
   - Generates `worker_instance_id = str(uuid.uuid4())`.
   - Initializes dedicated DatabaseManager with `settings.worker_db_pool_size`.
   - Initializes dedicated Elasticsearch client with `settings.elasticsearch_client_kwargs`.
   - Spawns background daemon thread emitting heartbeat to `worker_instances` every 10 seconds using its OWN independent SQLAlchemy session and database timestamp `func.now()`.
   - Spawns internal Python HTTP server on port 9102 serving `/metrics` directly from the process-local `MetricsCollector`.
   - Implements `run()` loop:
     - Check `self._is_draining`. If True, stop polling.
     - Acquire/renew lease with fencing token on `ingestion_checkpoints`.
     - Ingestion batch processing: If lease expires during cycle, abort batch commit immediately.
     - Exponential backoff with jitter on transient failures.
   - Signal handlers (`SIGINT`, `SIGTERM`):
     - Sets `self._is_draining = True`.
     - Allows active batch to complete ONLY if lease remains valid.
     - Updates `worker_instances.status = 'STOPPED'` using database `NOW()`.
     - Closes Elasticsearch and database connection pools.
     - Exits within bounded deadline (30 seconds max).
2. In `src/zylar/ingestion/engine.py`:
   - Conditional checkpoint commit:
     `UPDATE ingestion_checkpoints SET ... WHERE stream_id = :id AND lease_token = :token AND lease_generation = :gen`.
     If 0 rows updated, raise `FencedLeaseError` and rollback transaction.
3. In `api/main.py`:
   - In `lifespan`: If `settings.enable_ingestion_scheduler` is `False`, do NOT instantiate `CheckpointedIngestionWorker` or scheduler.
   - In `/api/ingestion/status`: Query PostgreSQL: join `ingestion_checkpoints` and `worker_instances` to report accurate worker liveness, heartbeat lag (`NOW() - last_heartbeat_at`), watermark lag, and lease generation.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_worker_runner.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/zylar/ingestion/runner.py src/zylar/ingestion/engine.py api/main.py tests/unit/test_worker_runner.py
git commit -m "feat(ingestion): implement dedicated worker runner, heartbeat persistence, and lease fencing contracts"
```

---

### Task 7.3: Detection Rule & Correlation Hardening

**Files:**
- Modify: `src/zylar/analysis/detection_rules.py`
- Modify: `src/zylar/analysis/correlation_service.py`
- Modify: `docs/plans/phase-6-detection-quality-and-observability.md`
- Create: `tests/unit/test_detection_rules_hardening.py`

**Interfaces:**
- Consumes: Raw event dictionaries.
- Produces: Segregated rules `RULE_RANSOMWARE_INDICATOR` and `RULE_RANSOMWARE_MASS_ENCRYPTION`, bounded node labels in `CorrelationGraphResult`, warning logging on betweenness calculation fallback.

- [ ] **Step 1: Write failing test for stateful per-entity ransomware rules and bounded graph inputs**

```python
# tests/unit/test_detection_rules_hardening.py
from datetime import UTC, datetime
from zylar.analysis.detection_rules import evaluate_detection_rules
from zylar.analysis.correlation_service import build_correlation_graph

def test_single_locked_file_triggers_indicator_not_mass_encryption():
    """A single event with .locked extension triggers indicator rule, not mass encryption."""
    single_event = [{
        "event_id": "ev-1",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "file_modification",
        "details": "User renamed file to important_doc.locked",
        "source_ip": "10.0.0.5",
        "user": "victim_alice",
    }]
    res = evaluate_detection_rules(single_event)
    rule_ids = [m.rule_id for m in res.rule_matches]
    assert "RULE_RANSOMWARE_INDICATOR" in rule_ids
    assert "RULE_RANSOMWARE_MASS_ENCRYPTION" not in rule_ids

def test_mass_encryption_requires_twenty_events_in_sliding_window_per_entity():
    """Mass encryption rule requires >= 20 file encryption events within sliding window for same entity."""
    events = [
        {
            "event_id": f"ev-{i}",
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "file_encryption",
            "details": f"File {i} encrypted with key",
            "source_ip": "10.0.0.5",
            "user": "victim_alice",
        }
        for i in range(20)
    ]
    res = evaluate_detection_rules(events, window_seconds=300)
    rule_ids = [m.rule_id for m in res.rule_matches]
    assert "RULE_RANSOMWARE_MASS_ENCRYPTION" in rule_ids

def test_correlation_graph_bounds_entity_strings_with_hash_suffix():
    """Excessively long entity strings must be safely bounded to 128 chars while preserving uniqueness."""
    long_user = "x" * 200
    events = [{
        "source_ip": "192.168.1.100",
        "user": long_user,
        "destination_port": 22,
        "timestamp": datetime.now(UTC).isoformat(),
    }]
    graph_res = build_correlation_graph(events)
    entity = graph_res.top_entities[0]
    assert len(entity) <= 128
    assert "_" in entity  # includes hash suffix
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_detection_rules_hardening.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement stateful rule segregation and correlation input bounds**

1. In `src/zylar/analysis/detection_rules.py`:
   - Split ransomware logic:
     - `RULE_RANSOMWARE_INDICATOR`: Triggered on individual events containing ransomware IOC keywords or extensions (`.locked`, `.encrypted`), confidence configurable via `RiskPolicy` (initial baseline 0.80).
     - `RULE_RANSOMWARE_MASS_ENCRYPTION`: Grouped by `(host/source_ip, user)` within sliding window (`window_seconds=300`). Triggered only when $\ge 20$ file encryption/modification events occur in that window for that entity, confidence configurable (initial baseline 0.98).
2. In `src/zylar/analysis/correlation_service.py`:
   - Enforce bounded entity length $\le 128$ characters: if length > 128, truncate to 119 chars and append `_` + first 8 characters of `sha256(raw_string)`.
   - Validate IP address literals with `ipaddress.ip_address` only for fields expected to be IP literals (`source_ip`, `destination_ip`).
   - In betweenness centrality computation: replace bare `except Exception:` with warning logging:
     `logger.warning("Betweenness centrality calculation failed; defaulting to 0.0: %s", type(exc).__name__)`.
3. In `docs/plans/phase-6-detection-quality-and-observability.md`:
   - Update documentation to reflect authoritative code weights ($25/25/20/15/15$) and graph limits ($250$ nodes, $600$ edges).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_detection_rules_hardening.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/zylar/analysis/ docs/plans/phase-6-detection-quality-and-observability.md tests/unit/test_detection_rules_hardening.py
git commit -m "fix(analysis): implement stateful ransomware rule segregation and bounded graph inputs"
```

---

### Task 7.4: Multi-Service Container Orchestration

**Files:**
- Create: `compose.yaml`
- Create: `docker/Dockerfile.api`
- Create: `docker/Dockerfile.worker`
- Create: `docker/Dockerfile.dashboard`
- Modify: `.dockerignore`
- Create: `tests/integration/test_compose_smoke.py`

**Interfaces:**
- Consumes: Python code, requirements in `pyproject.toml`, Docker Compose specification.
- Produces: Production-hardened container stack with dedicated `migration` one-shot service, non-root user `zylaruser` (UID 10001), isolated networks, loopback-only published ports, resource limits, and native healthchecks.

- [ ] **Step 1: Write integration smoke test using `docker compose config` validation**

```python
# tests/integration/test_compose_smoke.py
import subprocess
import shutil
import pytest
import yaml

def test_compose_config_validates_cleanly():
    """Validates compose.yaml structure, services, and health conditions using docker compose config or yaml parsing."""
    with open("compose.yaml", "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    services = data.get("services", {})
    assert "migration" in services, "compose must define a one-shot migration service"
    assert "api" in services
    assert "worker" in services
    assert "postgres" in services
    assert "elasticsearch" in services
    assert "dashboard" in services

    # API depends on migration completing successfully
    api = services["api"]
    deps = api.get("depends_on", {})
    assert "migration" in deps
    assert deps["migration"].get("condition") == "service_completed_successfully"

    # Worker depends on migration completing successfully
    worker = services["worker"]
    worker_deps = worker.get("depends_on", {})
    assert "migration" in worker_deps
    assert worker_deps["migration"].get("condition") == "service_completed_successfully"
    assert "ports" not in worker or len(worker["ports"]) == 0, "Worker must not publish host ports"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_compose_smoke.py -v`
Expected: FAIL with `AssertionError: compose must define a one-shot migration service`.

- [ ] **Step 3: Implement Dockerfiles, Compose stack, and non-root execution**

1. Create `docker/Dockerfile.api`:
   - Multi-stage build with Python 3.12-slim.
   - Pinned base images.
   - Creates system group and user `zylaruser` (UID 10001, GID 10001).
   - Installs dependencies from wheels/requirements.
   - Sets `USER zylaruser`.
   - Entrypoint: `uvicorn api.main:app --host 0.0.0.0 --port 8000`.
2. Create `docker/Dockerfile.worker`:
   - Identical base and security posture as API.
   - Sets `USER zylaruser`.
   - Entrypoint: `python -m zylar.ingestion.runner`.
3. Create `docker/Dockerfile.dashboard`:
   - Sets `USER zylaruser`.
   - Entrypoint: `streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0`.
4. Create root `compose.yaml`:
   - Services:
     - `postgres`: `image: postgres:16.8-alpine`, healthcheck via `pg_isready -U zylar_app -d zylar_db`, loopback port `127.0.0.1:5432:5432`.
     - `elasticsearch`: `image: docker.elastic.co/elasticsearch/elasticsearch:8.17.2`, single-node, healthcheck via `curl -f -k https://localhost:9200/_cluster/health`, loopback port `127.0.0.1:9200:9200`.
     - `migration`: Runs `alembic upgrade head` under `zylar_migration` credentials, depends on `postgres` healthy, restarts `no`.
     - `api`: Depends on `migration` (`service_completed_successfully`), `postgres` (`service_healthy`), `elasticsearch` (`service_healthy`). Bound to `127.0.0.1:8000:8000`.
     - `worker`: Depends on `migration` (`service_completed_successfully`), `postgres` (`service_healthy`), `elasticsearch` (`service_healthy`). No published host ports.
     - `dashboard`: Depends on `api` (`service_healthy`). Bound to `127.0.0.1:8501:8501`.
     - `prometheus`: Scrapes API and Worker, loopback port `127.0.0.1:9090:9090` (profile `monitoring`).
     - `kibana`: Profile `monitoring`.
     - `simulator`: Profile `sim`.
   - Networks: `zylar-frontend` (API, Dashboard), `zylar-backend` (API, Worker, Postgres, Elasticsearch).
   - Volumes: `postgres_data`, `es_data`, `prom_data`.
   - Resource limits: `deploy.resources.limits: cpus: '1.0', memory: 1G` for API/Worker.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_compose_smoke.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add compose.yaml docker/ .dockerignore tests/integration/test_compose_smoke.py
git commit -m "feat(deployment): implement compose orchestration with one-shot migration job and network isolation"
```

---

### Task 7.5: Distributed Observability & Metric Ownership

**Files:**
- Create: `docker/prometheus.yml`
- Modify: `src/zylar/core/metrics.py`
- Modify: `dashboard/app.py`
- Create: `tests/integration/test_distributed_metrics.py`

**Interfaces:**
- Consumes: API `:8000/metrics`, Worker `:9102/metrics`, PostgreSQL `worker_instances` table.
- Produces: Prometheus dual-target configuration, strictly commit-bounded metric counters (`zylar_workflow_events_completed_total`, `zylar_incidents_persisted_total`, `zylar_ingestion_checkpoint_advances_total`), Streamlit worker health cards.

- [ ] **Step 1: Write integration test for metric counter semantics and commit-boundary increments**

```python
# tests/integration/test_distributed_metrics.py
import pytest
from zylar.core.metrics import MetricsCollector

def test_metrics_counter_commit_boundary_semantics():
    """Counters must only increment upon successful transaction completion without high-cardinality labels."""
    collector = MetricsCollector()
    collector.record_workflow_events_completed(10)
    collector.record_incidents_persisted(1)
    collector.record_checkpoint_advance()

    out = collector.format_prometheus_exposition()
    assert "zylar_workflow_events_completed_total 10" in out
    assert "zylar_incidents_persisted_total 1" in out
    assert "zylar_ingestion_checkpoint_advances_total 1" in out
    # Ensure no raw event IDs or IP labels are exposed in Prometheus text
    assert "event_id=" not in out
    assert "source_ip=" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_distributed_metrics.py -v`
Expected: FAIL with `AttributeError`.

- [ ] **Step 3: Implement metric segregation and dashboard worker status**

1. In `src/zylar/core/metrics.py`:
   - Add segregated lifecycle methods:
     - `record_workflow_events_completed(count: int)`: Incremented when API/workflow returns.
     - `record_incidents_persisted(count: int)`: Incremented strictly upon successful PostgreSQL incident commit.
     - `record_checkpoint_advance()`: Incremented strictly upon successful checkpoint advancement transaction.
   - Enforce low-cardinality labels (`status`, `rule_name`, `error_class`). Reject high-cardinality labels (event IDs, usernames, IP addresses).
2. Create `docker/prometheus.yml`:
   ```yaml
   global:
     scrape_interval: 15s
   scrape_configs:
     - job_name: "zylar-api"
       static_configs:
         - targets: ["api:8000"]
     - job_name: "zylar-worker"
       static_configs:
         - targets: ["worker:9102"]
   ```
3. In `dashboard/app.py`:
   - Update sidebar to display separate status indicators:
     - API health (`/health/ready`)
     - Autonomous Ingestion Worker status: read from `/api/ingestion/status` (queries PostgreSQL `worker_instances` for hostname, last heartbeat, status, and lease generation).
     - Display warning alert if worker heartbeat is older than 30 seconds.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_distributed_metrics.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/zylar/core/metrics.py docker/prometheus.yml dashboard/app.py tests/integration/test_distributed_metrics.py
git commit -m "feat(observability): implement commit-bounded prometheus metrics and DB-backed dashboard telemetry"
```

---

### Task 7.6: Automated Database Backup & Disaster Recovery Verification Drill

**Files:**
- Create: `scripts/drills/backup_and_restore_drill.py`
- Create: `docs/runbooks/disaster-recovery-and-backup.md`
- Create: `tests/integration/test_backup_restore_drill.py`

**Interfaces:**
- Consumes: PostgreSQL connection string (`ZYLAR_DATABASE_URL`), `pg_dump` and `pg_restore` utilities.
- Produces: Semantic parity backup drill runner script with safety guards, automated integrity verification, disaster recovery runbook defining RPO/RTO targets and Elasticsearch recovery strategy.

- [ ] **Step 1: Write integration test for backup verification logic and safety guards**

```python
# tests/integration/test_backup_restore_drill.py
import pytest
from scripts.drills.backup_and_restore_drill import verify_database_parity, assert_restore_target_safety

def test_restore_target_safety_refuses_production_or_source_database():
    """Drill must refuse to restore if target database matches source database."""
    with pytest.raises(ValueError, match="Safety violation"):
        assert_restore_target_safety(source_db="zylar_db", target_db="zylar_db")

def test_verify_database_parity_checks_sequence_state():
    """Verification must fail if sequence last_value is less than max table ID."""
    source_seq = {"incidents_id_seq": {"last_value": 10, "is_called": True}}
    target_seq = {"incidents_id_seq": {"last_value": 5, "is_called": True}}
    with pytest.raises(ValueError, match="Sequence state mismatch"):
        verify_database_parity(
            source_counts={"incidents": 10},
            target_counts={"incidents": 10},
            source_sequences=source_seq,
            target_sequences=target_seq,
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_backup_restore_drill.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement drill runner and disaster recovery runbook**

1. Create `scripts/drills/backup_and_restore_drill.py`:
   - Safety guard: Target database MUST be explicitly specified and MUST NOT equal source database (`zylar_restore_test` default).
   - Executes `pg_dump -Fc` (custom format). Computes SHA-256 digest of dump file.
   - Restores dump into `zylar_restore_test` using `pg_restore`.
   - Semantic parity verification:
     - Table schemas and foreign key constraints match.
     - Row counts across `incidents`, `users`, `worker_instances`, `ingestion_checkpoints`, `dead_letter_events`, `audit_logs` match.
     - Sequence `last_value` and `is_called` match to guarantee future generated IDs cannot collide with restored records.
     - Data smoke test: executes sample read and insert against `zylar_restore_test`.
   - Cleans up `zylar_restore_test` on completion.
2. Create `docs/runbooks/disaster-recovery-and-backup.md`:
   - Documents target RPO: $\le 1$ hour for logical dumps; target $\le 5$ minutes for continuous WAL archiving.
   - Documents target RTO: $\le 30$ minutes to restore operational state.
   - Specifies Elasticsearch recovery strategy: snapshot repository configuration, event log replay from cold storage, and watermark reset runbook.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_backup_restore_drill.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/drills/backup_and_restore_drill.py docs/runbooks/disaster-recovery-and-backup.md tests/integration/test_backup_restore_drill.py
git commit -m "feat(drills): implement semantic parity backup restoration drill and disaster recovery runbook"
```

---

### Task 7.7: Operational Runbooks & Architectural Decision Records

**Files:**
- Create: `docs/runbooks/incident-investigation-runbook.md`
- Create: `docs/runbooks/worker-failover-and-recovery.md`
- Create: `docs/runbooks/database-migration-and-rollback.md`
- Create: `docs/runbooks/elasticsearch-outage-and-recovery.md`
- Create: `docs/runbooks/secret-rotation-and-credential-hygiene.md`
- Create: `docs/runbooks/llm-degradation-and-deterministic-fallback.md`
- Create: `docs/adr/README.md`
- Create: `docs/adr/ADR-001-postgresql-and-elasticsearch-dual-storage.md`
- Create: `docs/adr/ADR-002-optional-llm-inference-and-provider-isolation.md`
- Create: `docs/adr/ADR-003-bounded-worker-and-monotonic-leases.md`
- Create: `docs/adr/ADR-004-deferring-kafka-and-kubernetes.md`
- Create: `docs/adr/ADR-005-security-identity-and-secret-management.md`
- Create: `docs/adr/ADR-006-observability-and-metric-ownership.md`

- [ ] **Step 1: Author all 6 operational runbooks with concrete CLI commands and escalation checklists**
- [ ] **Step 2: Author all 6 MADR-formatted ADRs detailing context, decisions, and consequences**
- [ ] **Step 3: Verify markdown links and references across all documentation**
- [ ] **Step 4: Commit**

```bash
git add docs/runbooks/ docs/adr/
git commit -m "docs(runbooks,adr): add operational runbooks and architectural decision records with provider-isolated LLM"
```

---

### Task 7.8: End-to-End Portfolio Evidence Package & Verification Gate

**Files:**
- Create: `scripts/demo_scenario.py`
- Create: `docs/architecture/system-architecture.md`
- Create: `docs/architecture/threat-model.md`
- Modify: `README.md`
- Create: `tests/integration/test_demo_scenario.py`

**Interfaces:**
- Consumes: Running Zylar stack (API, Worker, PostgreSQL, Elasticsearch).
- Produces: Non-destructive portfolio demonstration script with separate dry-run mode, STRIDE threat model, updated system architecture, and audited `README.md`.

- [ ] **Step 1: Write integration test for dry-run validation and isolated demo execution**

```python
# tests/integration/test_demo_scenario.py
from scripts.demo_scenario import run_demo_lifecycle

def test_dry_run_mode_performs_zero_persistent_writes():
    """dry_run=True must validate connectivity and plan steps, producing zero persistent incidents."""
    summary = run_demo_lifecycle(mode="dry_run")
    assert summary["status"] == "DRY_RUN_PASSED"
    assert summary["incidents_created"] == 0

def test_demo_mode_executes_in_isolated_environment():
    """mode='demo' generates unique run ID and tests replay idempotency and worker restart."""
    summary = run_demo_lifecycle(mode="demo", test_stream_prefix="test-soc")
    assert summary["status"] == "SUCCESS"
    assert summary["incidents_created"] == 1
    assert summary["replay_duplicates_created"] == 0
    assert summary["worker_restart_resumed"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_demo_scenario.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement demo scenario, architecture docs, threat model, and README audit**

1. Create `scripts/demo_scenario.py`:
   - Accepts `--mode [dry_run|demo]`.
   - In `dry_run`: Tests connection to Elasticsearch and PostgreSQL, validates schemas, outputs plan, exits with 0 persistent writes.
   - In `demo`: Generates unique `demo_run_id = uuid4()`, creates isolated test stream `demo-{demo_run_id}`, creates demo index in Elasticsearch.
     - Ingests simulated brute force events.
     - Worker processes batch and commits incident.
     - Asserts exactly 1 incident created.
     - Tests replay idempotency: re-running identical event batch creates 0 new incidents.
     - Tests worker restart: restarts worker process and verifies it resumes cleanly from committed checkpoint.
     - Cleans up only the test stream and demo index.
2. Create `docs/architecture/system-architecture.md`:
   - Mermaid architecture, sequence, and data-flow diagrams.
3. Create `docs/architecture/threat-model.md`:
   - STRIDE threat model covering trust boundaries, credential leakage, DoS, and prompt injection.
4. Audit `README.md`:
   - Synchronize all architecture diagrams, installation guides, Docker Compose commands, and benchmark disclosures (`synthetic-baseline-v1`).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_demo_scenario.py -v`
Expected: PASS

- [ ] **Step 5: Run full test suite, Ruff linting, and Mypy across all packages**

Run:
```bash
pytest
ruff check .
mypy src api dashboard scripts tests
```
Expected: PASS with 0 errors.

- [ ] **Step 6: Commit**

```bash
git add scripts/demo_scenario.py docs/architecture/ README.md tests/integration/test_demo_scenario.py
git commit -m "feat(portfolio): implement non-destructive demo scenario, threat model, and synchronize README"
```

---

## Phase 7 Acceptance Criteria

1. **Process Separation:** API container handles requests with `enable_ingestion_scheduler=false` with zero background polling; Worker container executes `zylar.ingestion.runner` with `enable_ingestion_scheduler=true` with no public host ports.
2. **Table-Specific Least Privilege:** Runtime application functions under `zylar_app` with restricted table DML (audit logs strictly append-only, sequences `USAGE` only); schema migrations execute cleanly under `zylar_migration`.
3. **Durable Identity & Worker Heartbeats:** Users and password hashes survive process restart in PostgreSQL with concurrency-safe advisory-locked bootstrap; Worker instances emit live heartbeats to PostgreSQL decoupled from lease ownership.
4. **Elasticsearch TLS:** Client enforces HTTPS, credentials, and optional `ca_certs` in production mode, failing closed on insecure configurations.
5. **Drill Verification:** Automated backup and restore drill verifies semantic parity across schemas, row counts, sequence states, and data integrity smoke tests with target RPO/RTO disclosures.
6. **Operational Readiness:** All 6 runbooks and 6 ADRs (including provider-isolated LLM) are complete, technically accurate, and cross-linked.
7. **Portfolio Demo:** `demo_scenario.py` provides distinct `dry_run` and `demo` modes, demonstrates replay idempotency and worker restart recovery without requiring production secrets or destructive operations.
8. **Regression Suite:** 100% of unit and integration tests pass with 0 failures, clean Ruff linting, and clean Mypy type-checking across `src`, `api`, `dashboard`, `scripts`, and `tests`.
