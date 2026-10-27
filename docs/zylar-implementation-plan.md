# Zylar — Final Implementation Plan

**Version:** 1.0
**Date:** 25 October 2026
**Goal:** Turn Zylar into a production-oriented, locally operated AI-assisted SOC portfolio project with verifiable engineering evidence.

## 1. Executive decision

Keep Zylar as a **modular monolith** with FastAPI as the application/API boundary, LangGraph as workflow orchestration, Elasticsearch as the security-event search engine, PostgreSQL as the transactional system of record for SOC application state, and Ollama as the local inference runtime. Keep Streamlit as the initial analyst UI.

Do **not** add Kafka, Redis, Kubernetes, microservices, or autonomous remediation in this implementation cycle. Introduce a bounded worker process only when workflow execution is moved out of request handlers; initially it can use PostgreSQL-backed execution records and a bounded worker loop. Add a dedicated queue only if measured requirements justify it.


### Target architecture


```text
Synthetic/real security sources
            |
            v
Event ingestion -> schema validation / normalization
            |                        |
            v                        v
    Elasticsearch              PostgreSQL
    searchable logs             application state:
                                 incidents, evidence refs,
                                 executions, audit, history
            |                        ^
            v                        |
     Detection/rules/ML -> correlation/risk -> workflow
                                      |
                            Ollama local inference
                                      |
                            advisory mitigation plan
                                      |
                            FastAPI -> Streamlit UI
```

**Data ownership**

- **Elasticsearch:** raw/searchable logs and event investigation queries.
- **PostgreSQL:** incident lifecycle, normalized event identity/deduplication records, execution status/checkpoints, entity/risk history, audit events, and report metadata.
- **Ollama:** local model inference only; it is not a database or source of truth.
- **Dashboard:** calls FastAPI; it must not connect directly to either database.
- **Mitigation:** recommendations remain advisory. No shell commands or destructive actions are executed automatically.

## 2. Source-based baseline and known gaps

The supplied ZIP confirms the existing top-level modules: agents/, api/, dashboard/, elk_setup/, log_generator/, memory/, orchestrator/, reports/, tests/, README.md, and requirements.txt. The repository is a prototype baseline, not a production-ready implementation.

Verified issues from the source review:

1. `agents/classifier_agent.py` uses `ChatOpenAI`/`gpt-3.5-turbo`, contradicting the README's claim of local-only inference.
2. `api/main.py` accepts arbitrary, insufficiently bounded event dictionaries; has no visible authentication/RBAC; returns exception details; performs blocking Elasticsearch/workflow calls in async routes; and does not retain/manage scheduler lifecycle cleanly.
3. Event schema mismatch: normalization writes `user`, while correlation/risk logic reads `username`.
4. The simulator does not reliably supply `destination_port`, although port-scan logic expects it.
5. `memory/sqlite_manager.py` stores incidents and entity/risk history with ad hoc SQLite calls; incident writes and recurrence updates are not an atomic lifecycle. A random incident ID is not event-batch idempotency.
6. `elk_setup/docker-compose.yml` uses Elasticsearch/Kibana 8.9.0 with `elasticsearch==7.17.9` in `requirements.txt`, and disables Elasticsearch security.
7. The dashboard shows hardcoded health state and makes HTTP requests without explicit timeouts.
8. The ZIP contains `.git/`, Python bytecode caches, a tracked local SQLite database, and previously reviewed repository metadata indicates that a virtual environment was tracked. These items must be removed from source control.
9. The existing tests cover only a narrow part of anomaly detection. A reproducible Python runtime/test baseline must be established before claiming passing tests.
Do not describe the current application as fully autonomous, self-evolving, production-ready, or performing automated remediation. Update claims only after evidence exists.


## 3. Scope and non-goals


### In scope

- Reproducible packaging and repository hygiene.
- Centralized, validated configuration and structured logging.
- Canonical event schema.
- API authentication, authorization, input limits, safe errors, health endpoints.
- Local-only Ollama adapter and deterministic fallback.
- PostgreSQL schema, migrations, transactional repositories, SQLite data migration, idempotency.
- Replay-safe ingestion and bounded workflow execution.
- Detection/risk evaluation, observability, secure Compose deployment, CI, recovery documentation and portfolio evidence.

### Explicit non-goals for this delivery

- Microservices or Kubernetes.
- Kafka or Redis without measured need.
- Automatic execution of mitigation/remediation.
- Claims of enterprise/SOC compliance or production certification.
- A full frontend rewrite.
- Storing every raw security log in PostgreSQL when Elasticsearch can retain and search it.

## 4. Dependency order


```text
Slice 1: Repository hygiene + packaging + baseline CI
   |
Slice 2: Settings + canonical event model + simulator alignment
   |
Slice 3: API auth/RBAC + limits + safe errors + health
   |
Slice 4: Ollama-only adapter + validated output + fallback
   |
Slice 5: PostgreSQL schema + Alembic + repositories + idempotency
   |
Slice 6: Checkpointed ingestion + bounded worker + recovery
   |
Slice 7: Detection evaluation + risk/correlation tests + metrics
   |
Slice 8: Secure deployment + runbooks + interview evidence
```

Slices 2–4 can proceed in parallel after Slice 1 if separate branches are kept small, but API security and canonical input validation must be in place before exposing more workflow functionality. PostgreSQL must be established before durable execution/checkpointing is implemented.


## 5. Implementation slices


### Slice 1 — Repository hygiene, packaging, runtime and CI


#### Changes

- Add `pyproject.toml` with declared supported Python versions, runtime/dev dependency groups, Ruff, a type checker, pytest, coverage configuration, and package build.
- Start moving application code toward `src/zylar/`. Preserve adapters around the existing agents initially; do not rewrite the whole project in one step.
- Establish one canonical development command path and lock/test dependency versions. Ensure the Elasticsearch client version is tested against the configured server API before pinning the pair.
- Add `.gitignore` rules for `.venv/`, `venv/`, `__pycache__/`, `*.py[cod]`, `.env*` except `.env.example`, `*.db`, generated reports, coverage output, build output, and local model artifacts.
- Remove tracked virtual environments, caches, local databases, generated reports, and unnecessary `.git/` archive content from the repository using a dedicated commit. Do not delete useful project source or historical progress. If secrets or sensitive incident records were committed, assess Git history separately.
- Add `.env.example` with safe placeholders for PostgreSQL URL, Elasticsearch URL, Ollama URL/model, auth signing-key placeholder, log level, request/batch limits, and service timeouts.
- Create `core/settings.py` with typed settings and validation; remove hardcoded URLs, model names, and runtime configuration from routes, agents, dashboard, and simulator.
- Add structured logging with request/execution/incident identifiers, duration, and error category; never log credentials or full sensitive event payloads by default.
- Repair the README's installation commands and label existing functionality accurately.

#### Acceptance

- A clean checkout installs with documented commands.
- Lint, type-check, unit-test, and package-build commands run in the declared Python version.
- `git ls-files` contains no virtual environment, bytecode, local DB, generated reports, or secrets.
- No service URL/model name/secret is unexpectedly hardcoded in application code.
- Existing prototype flow still runs with development dependencies.

### Slice 2 — Canonical event model and simulator alignment

Add Pydantic domain contracts, initially under src/zylar/domain/:

- `NormalizedEvent`: stable `event_id`, UTC-aware timestamp, event type, source IP, canonical `user`, status, optional `destination_port`, details, source/index/document reference, and payload hash.
- `WorkflowRequest`: bounded event list, request size constraints, strict field validation, and duplicate event-ID policy.
- `IncidentResponse`, `HealthResponse`, `ErrorResponse`, and validated workflow status models.
Normalize source/provider-specific records once at ingestion. Use user everywhere; do not support user and username as two internal canonical names. Update the simulator to emit destination_port for port scans and include stable IDs and timestamps. Treat missing optional fields explicitly rather than silently inventing evidence.


#### Acceptance

- Invalid timestamps, malformed IPs where required, unsupported types, invalid port ranges, oversize batches, and duplicate IDs have defined behavior.
- Every accepted event has a stable identity and timezone-aware UTC timestamp.
- Fixed fixtures cover benign traffic, brute force, port scan, ransomware indicators, and lateral movement.
- Regression tests show correlation and risk code receives the canonical fields.

### Slice 3 — API security, validation and health


#### Changes

- Add authentication and role-based authorization: `admin`, `analyst`, `viewer`. Ingestion/workflow execution require analyst/admin; read operations allow viewer; administrative controls require admin.
- Use a maintained, well-understood auth mechanism with hashed credentials or a well-scoped identity integration. If JWT is used, validate issuer/audience/expiry and rotate the signing secret. Store secrets in environment variables or deployment secrets, not Git.
- Apply request body limits, event-count limits, pagination, strict models, and rate limits appropriate to the deployment exposure.
- Return generic error envelopes with correlation IDs. Log detailed exceptions server-side with redaction.
- Move blocking I/O out of async request handlers: prefer supported async clients, or use a deliberately bounded thread pool for synchronous operations.
- Add `/health/live` and `/health/ready`. Readiness should check configured PostgreSQL and Elasticsearch dependencies with short deadlines; Ollama readiness policy must distinguish required from degraded/optional inference.
- Add explicit client timeouts in dashboard HTTP requests and make UI health indicators reflect actual backend responses.
- Use FastAPI lifespan for resource creation/cleanup; do not start unmanaged background tasks at module import time.

#### Acceptance

- Missing credentials yield 401; authenticated but unauthorized roles yield 403.
- Oversized or invalid input returns 413/422 as appropriate without tracebacks or secrets.
- Health endpoints reflect dependency failures and have bounded response time.
- API contract and authorization matrix tests pass.
- No database or HTTP client is initialized afresh for every request unnecessarily.

### Slice 4 — Local Ollama inference and deterministic fallback


#### Changes

- Replace `ChatOpenAI` with a `LocalLLMClient`/Ollama adapter configured from typed settings.
- Ensure all SOC classifier/threat/mitigation-planning model calls use the local endpoint only. Remove unnecessary `langchain_openai` dependencies/configuration if no use remains.
- Set connect/read deadlines, bounded retries only for retryable failures, event-context size limits, and output/token constraints where supported.
- Validate model output against a strict Pydantic schema; reject malformed or unexpected fields.
- Use deterministic fallbacks for timeouts, unavailable Ollama, and invalid output. A fallback must clearly mark LLM analysis as unavailable rather than fabricating threat intelligence.
- Treat event strings and model output as untrusted. Redact unnecessary personal/secret values and never execute model-generated commands.

#### Acceptance

- Tests mock Ollama success, timeout, unavailable service, malformed JSON, schema violation, and prompt-injection-like log content.
- Network/configuration tests demonstrate no external AI provider is used by the application.
- Output is validated before it affects risk/incident fields.
- Mitigation output remains advisory and non-executable.

### Slice 5 — PostgreSQL incident lifecycle, Alembic and idempotency

**Database decision:** PostgreSQL is the transactional system of record for application state. Elasticsearch remains the event-search store. Do not copy every full raw log to PostgreSQL by default.


#### Initial tables

- `events`: stable `event_id`, payload hash, normalized fields/reference, event timestamp, first-seen metadata.
- `workflow_executions`: execution ID, source/cursor range, status, attempt count, timing, failure code and checkpoint metadata.
- `incidents`: lifecycle status, severity, risk score/category, idempotency key, evidence/scoring versions, created/updated timestamps.
- `incident_events`: incident-to-event relationship with unique constraints.
- `entity_history`: IP/user recurrence observations; use a typed entity kind and stable normalized identity.
- `risk_history`: incident/entity risk observations and policy version.
- `audit_events`: actor, action, resource, timestamp, outcome, correlation ID and safe metadata.
- `report_artifacts`: incident reference, format, storage location/hash, generation status, creation time.

#### Implementation

- Add SQLAlchemy 2.x models and Alembic migrations. Pick sync or async consistently; recommendation: use async SQLAlchemy + `asyncpg` if the API is async end-to-end, otherwise use synchronous SQLAlchemy only in a bounded sync execution context. Do not mix session styles ad hoc.
- Add repositories and transaction-scoped session dependencies. Keep SQL out of routes and LangGraph nodes where possible.
- Use database-native upserts/unique constraints for races. Define foreign keys, check constraints, indexes and deletion/retention behavior.
- Define incident idempotency from stable event IDs plus detection/rule/model/prompt version inputs, not random UUID alone. Use unique constraints as the concurrency authority.
- Make incident and evidence-link creation atomic. Entity recurrence updates must be in the same transaction or derive from unique incident observations to avoid double-counting retries.
- Keep a JSON representation of report content with the incident; generate PDF as a retryable artifact after the transaction commits.
- Store timestamps as timezone-aware UTC.
- Create a one-time migration command that imports existing `memory/zylar_memory.db` data into PostgreSQL, validates row counts and fields, and is safe to rerun or explicitly refuses a second import. Back up the old SQLite DB first. Do not delete the source DB until verification is complete.
- Keep SQLite only for limited isolated unit tests if needed; use PostgreSQL integration tests for SQL/concurrency behavior.

#### Acceptance

- `alembic upgrade head` works on a blank PostgreSQL database.
- Migration can be run against test fixtures and validated for counts, identifiers, timestamps, scores, and JSON fields.
- Replaying identical events does not create duplicate incidents, joins, audit effects, or recurrence increments.
- Concurrent incident creation remains consistent.
- A failed PDF export does not lose the committed incident.
- Backup and restore procedures are tested.

### Slice 6 — Replay-safe ingestion and bounded workflow execution


#### Changes

- Replace 30-second timestamp-window polling with a persistent cursor/checkpoint containing source, timestamp watermark, deterministic tie-breaker event ID, and last successful execution.
- Query Elasticsearch with stable sort `(timestamp, event_id or stable document ID)`, bounded page size, and a configurable overlap window.
- Deduplicate events against PostgreSQL stable event IDs. Define how late-arriving or equal-timestamp events are handled.
- Add explicit workflow states: `queued`, `running`, `succeeded`, `failed`, `retryable`, `cancelled`.
- Move expensive LangGraph + local inference processing out of request handlers. The API should submit execution and return `202 Accepted` with an execution ID. Use a bounded worker process and PostgreSQL-backed claims/leases for the first deployment.
- Use atomic claiming/lease expiry to prevent two worker instances from processing one execution simultaneously. Use explicit attempt limits and backoff; avoid retrying validation and permanent errors.
- Persist checkpoint/evidence around workflow nodes where recovery is valuable. Model state should be explicit and validated.
- Manage scheduler/worker lifecycle and graceful shutdown via lifespan for single-process mode, or a dedicated worker entry point for worker mode. Avoid multiple API workers each running their own poller.
- Add limits for graph/event batch size and agent context size.

#### Acceptance

- Restarting during a workflow resumes or safely retries without duplicate incidents.
- Overlapping polling windows and duplicate source results do not create repeated effects.
- A slow/unavailable dependency marks execution state correctly and preserves audit evidence.
- Worker concurrency is bounded; execution claims expire safely after process crash.
- API stays responsive while inference runs.
- No workflow execution is silently dropped.

### Slice 7 — Detection quality, risk/correlation and observability


#### Detection

- Separate deterministic rule evidence from Isolation Forest anomaly score. Statistical outliers are candidates for investigation, not confirmed attacks.
- Add windowed features: failed logins per IP/user, unique destination ports per source, relevant write/rename indicators for ransomware fixtures, and rare source/network signals where input supports them.
- Version rule sets, feature definitions, Isolation Forest parameters/artifact, scoring policy, and prompt templates. Persist the versions and evidence used for each incident.
- Refactor risk scoring into a pure deterministic service with one policy configuration and explicit missing-value behavior. Test boundary values and score reproducibility.
- Define correlation graph semantics and maximum nodes/edges; handle empty/disconnected/malformed graphs; use canonical `user` field.
- Build immutable labeled synthetic fixtures and record precision, recall, F1, false-positive rate, and end-to-end detection latency. Clearly document synthetic data limits; do not present synthetic-only metrics as real-world SOC performance.

#### Observability

- Add metrics for ingested/deduplicated events, workflows by status, processing/node latency, dependency failures, detections by rule, risk bands, and report-export failures.
- Use JSON logs with request/execution/incident IDs and redaction.
- Dashboard must show real readiness/degraded state, explicit timeouts, pagination, safe rendering and useful error messages.
- Use escaped Graphviz input or a structured renderer; do not interpolate untrusted event strings into raw graph markup.

#### Acceptance

- Fixed labeled fixtures produce a versioned evaluation report with metrics.
- Same evidence and policy version yields the same deterministic risk score.
- Edge case and load-bound tests exist for correlation.
- Dashboard health is driven by `/health/ready`; dependency failure is visible.

### Slice 8 — Secure deployment, recovery and portfolio evidence


#### Deployment

- Add root `compose.yaml` for API, worker, dashboard, PostgreSQL, Elasticsearch, Kibana and optional simulator.
- Keep service ports bound to localhost by default for local use; use named private networks. Do not expose the Elasticsearch/Kibana management surface publicly.
- Enable Elasticsearch security for any deployment not strictly isolated. Add health checks, persistent volumes, dependency readiness, resource limits, and compatible version pins.
- Confirm Elasticsearch Python client/server compatibility in integration CI before selecting a version pair; the current client 7.17.9 with server 8.9.0 must be resolved, not assumed compatible.
- Use least-privilege PostgreSQL roles: migration role for deployment/migrations and runtime role with only required data access. Use environment/secrets injection and avoid default production passwords.
- Document backups, restore validation, schema upgrade and rollback constraints. Do not claim backup readiness until restore is tested.

#### CI

- Format/lint, type-check, unit tests, API/security tests, PostgreSQL integration/migration tests, dependency/security scan, build/package check, and Compose smoke test.
- Use GitHub Actions service containers or Compose with per-run credentials generated for CI; never reuse production credentials.
- Pin action versions and grant minimum workflow token permissions. Do not print secrets into logs.

#### Documentation and interview evidence

- Architecture/data-flow diagram.
- Threat model and trust boundaries.
- Environment/configuration guide.
- DB schema/migration and data-flow rationale.
- Detection evaluation report and synthetic-data limitations.
- Incident investigation and recovery runbooks.
- Backup/restore and worker-restart drill evidence.
- Reproducible demo scenarios and short demo recording.
- ADRs explaining PostgreSQL vs Elasticsearch roles, local-only inference, worker design, idempotency, and why Kafka/Kubernetes were deferred.
- README claims must match code and test evidence.

#### Acceptance

- Clean setup reaches all readiness checks with documented commands.
- DB restore and worker restart drills complete using runbooks.
- CI blocks merge if required tests, migrations, lint/type/build or security checks fail.
- Demo shows event ingestion → normalized evidence → deterministic detection/ML signal → local classifier or explicit fallback → persisted incident → advisory mitigation → audited report.

## 6. Test matrix


| Layer | Required coverage |
| --- | --- |
| Unit | normalization, IDs/hash, invalid fields, rule boundaries, score policy, Ollama schema/fallback, graph edge cases |
| API/security | auth/RBAC matrix, body/event limits, pagination, safe errors, health and degraded states |
| Persistence | fresh migrations, SQLite migration validation, transactions, upserts, idempotency, concurrent creation, report failure |
| Workflow | duplicate batches, checkpoint ordering, late events, restart recovery, lease expiry, retries/timeouts, dependency outages |
| Evaluation | fixed benign/attack fixtures with precision, recall, F1, FPR and latency |
| Deployment | clean Compose startup, readiness, client/server compatibility, secret handling, backup/restore |
| Regression | all existing public API and dashboard paths retain intended behavior while changing implementation |


## 7. Delivery checklist and commit plan

Use a feature branch and one reviewable commit/PR per slice. Do not mix repository history cleanup, schema migration and UI changes in one large commit.

1. `chore: clean repository and establish reproducible tooling`
2. `refactor: add typed settings and canonical event contracts`
3. `feat: secure API with authentication and role authorization`
4. `refactor: route all LLM inference through local Ollama`
5. `feat: add PostgreSQL persistence and Alembic migrations`
6. `feat: make incident processing idempotent`
7. `feat: add checkpointed ingestion and bounded worker execution`
8. `test: evaluate detection, risk scoring, and correlation quality`
9. `feat: add observability and real dependency health`
10. `ops: secure Compose deployment and recovery runbooks`
11. `docs: publish architecture, threat model and portfolio demo`

## 8. Release gates

The portfolio release is ready only when all these gates pass:

- [ ] Clean install and documented startup on a declared Python version.
- [ ] No secrets, local DBs, generated reports, venv or bytecode are tracked.
- [ ] No external AI inference path remains.
- [ ] API auth/RBAC and input validation are tested.
- [ ] PostgreSQL migration, idempotency, and concurrent writes are tested.
- [ ] Ingestion cursor and workflow recovery survive restart.
- [ ] Detection evaluation report is reproducible and limitations are disclosed.
- [ ] Logs, health and metrics are useful and do not leak sensitive data.
- [ ] Compose, image/client compatibility, migration, backup and restore are tested.
- [ ] CI enforces required checks.
- [ ] README makes only evidence-backed claims.
- [ ] Demo shows the complete event-to-incident path and clearly identifies mitigation as advisory.

## 9. Estimate and execution recommendation

A realistic planning estimate is **4–6 weeks of focused solo work** for a credible, tested portfolio release, subject to the existing runtime being reproducible and the actual migration complexity. This is not a guarantee and should be updated after Slice 1 establishes the baseline.

Start with Slice 1, then slices 2–4 before touching UI polish or adding agent features. The highest-risk technical work is PostgreSQL migration/idempotency and replay-safe ingestion. Keep each slice small, runnable and test-backed.


## 10. Current release statement

The current ZIP represents a functional prototype foundation, not a production-certified SOC. The target outcome is a **production-oriented local SOC application with documented controls, measured detection quality, reproducible deployment, and test evidence**. Use the phrase “production-ready” only after the release gates and relevant operational/security reviews have actually passed.
