# Zylar Security Architecture & STRIDE Threat Model

## 1. Overview & Trust Boundaries

Zylar processes security event telemetry and executes incident mitigation. The platform enforces defense-in-depth across six distinct trust zones:
- **Trust Zone 0 (External Untrusted Network)**: Untrusted client traffic, event log sources, and internet perimeter.
- **Trust Zone 1 (Frontend Ingress)**: Streamlit Dashboard and external API consumers.
- **Trust Zone 2 (Application Runtime)**: FastAPI backend and Background Ingestion Worker.
- **Trust Zone 3 (Storage System of Record)**: PostgreSQL database engine.
- **Trust Zone 4 (Search & Log Store)**: Elasticsearch cluster.
- **Trust Zone 5 (Local Inference)**: Ollama local LLM runtime.

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing

| Threat ID | Threat Description | Attack Vector | Mitigation Control | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **S-01** | Operator Identity Spoofing | Attacker forges JWT access token to execute administrative workflows. | Cryptographic HMAC-SHA256 token verification with high-entropy `ZYLAR_JWT_SECRET` ($\ge 32$ chars). Strict expiration ($60\text{ min}$). | **VERIFIED** in `tests/api/test_auth_rbac.py` |
| **S-02** | Worker Impersonation | Rogue process attempts to claim stream leadership and commit arbitrary watermarks. | Monotonic lease fencing tokens (`lease_generation`). Stale workers rejected via conditional SQL updates (`FencedLeaseError`). | **VERIFIED** in `tests/integration/test_worker_lifecycle_fencing.py` |
| **S-03** | Upstream Event IP Spoofing | Attacker injects forwarded client IP headers (`X-Forwarded-For`). | Untrusted proxy client IP resolution rejects forged headers unless received from explicit `trusted_proxies`. | **VERIFIED** in `tests/api/test_security_sanitization.py` |

### 2.2 Tampering

| Threat ID | Threat Description | Attack Vector | Mitigation Control | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **T-01** | Database Record Tampering | SQL injection in API queries alters incident or checkpoint records. | Parameterized queries via SQLAlchemy 2.0 typed ORM; zero raw string interpolation. Table-specific grants prohibit schema tampering. | **VERIFIED** in `tests/unit/test_setup_postgres_roles.py` |
| **T-02** | Stream Watermark Rewind | Stale or delayed worker attempts to commit older stream watermark. | Conditional watermark update: `WHERE lease_token = :token AND lease_generation = :expected_gen`. Replay deduplication prevents duplicate incidents. | **VERIFIED** in `tests/integration/test_ingestion_checkpointing.py` |
| **T-03** | Malformed Poison Event Injection | Attacker submits malformed JSON or unparseable timestamps to crash ingestion. | Schema validation diverts malformed records to `dead_letter_events` without halting pipeline processing. | **VERIFIED** in `tests/integration/test_ingestion_checkpointing.py` |

### 2.3 Repudiation

| Threat ID | Threat Description | Attack Vector | Mitigation Control | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **R-01** | Denied Mitigation Action | Operator denies executing an account block or IP firewall modification. | Immutable, append-only `audit_logs` table records actor, timestamp, action, and sanitised metadata. | **VERIFIED** in `tests/unit/test_setup_postgres_roles.py` |
| **R-02** | Denied Incident Modification | Attacker claims incident resolution occurred without authorization. | State transitions require authenticated user session with RBAC enforcement (`ANALYST` or `ADMIN`). | **VERIFIED** in `tests/api/test_auth_rbac.py` |

### 2.4 Information Disclosure

| Threat ID | Threat Description | Attack Vector | Mitigation Control | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **I-01** | Secret Leakage via Diagnostics | Database passwords or Elasticsearch API keys leaked in error logs or `/health` probes. | Global exception handler sanitizes URLs and error payloads via `re.sub(r":([^/@:]+)@", ":***@", msg)`. `SecretStr` used for passwords. | **VERIFIED** in `tests/api/test_health_probes.py` |
| **I-02** | Credential Exfiltration via Database | Compromised application role queries password hashes from `users`. | Role `zylar_read` cannot read password hashes. Column-level permissions prevent unauthorized hash exposure. | **VERIFIED** in `tests/unit/test_setup_postgres_roles.py` |
| **I-03** | Elasticsearch Man-in-the-Middle | Cleartext HTTP communication intercepted on internal network. | Production mode enforces HTTPS and certificate verification (`verify_certs=True`, `ca_certs`). | **VERIFIED** in `tests/unit/test_settings.py` |

### 2.5 Denial of Service (DoS)

| Threat ID | Threat Description | Attack Vector | Mitigation Control | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **D-01** | Database Connection Exhaustion | High concurrency of API requests exhausts PostgreSQL connection pool. | Process-specific connection budgeting: `api_db_pool_size` (10) + `worker_db_pool_size` (5) $\le C_{\text{max}}$. | **VERIFIED** in `tests/unit/test_settings.py` |
| **D-02** | Threat Graph Memory Blowup | Large volume of events causes NetworkX correlation graph to consume gigabytes. | Bounded graph construction limits: `max_events=500`, `max_nodes=250`, `max_edges=600`. Node strings bounded to $\le 128$ chars. | **VERIFIED** in `tests/unit/test_detection_rules_hardening.py` |
| **D-03** | Slow Inference DoS | Slow LLM generation ties up worker threads indefinitely. | Strict circuit breaker: $5.0\text{s}$ timeout with fallback to deterministic rule mitigation templates. | **VERIFIED** in `tests/api/test_health_probes.py` |

### 2.6 Elevation of Privilege

| Threat ID | Threat Description | Attack Vector | Mitigation Control | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **E-01** | User Self-Promotion to Admin | Application user executes `INSERT INTO users (..., role) VALUES (..., 'ADMIN')`. | Column-level `INSERT` restrictions on `public.users` grant application role permissions on user fields excluding `role`. Defaults to `ANALYST`. | **VERIFIED** in `tests/unit/test_setup_postgres_roles.py` |
| **E-02** | Database Administrative Elevation | Application role executes `ALTER TABLE` or `DROP TABLE` to destroy audit logs. | `zylar_app` role possesses zero DDL privileges. Schema owner is exclusively `zylar_migration`. | **VERIFIED** in `tests/unit/test_setup_postgres_roles.py` |
| **E-03** | Container Escape | Compromised container attempts to gain host root privileges. | All container images (`api`, `worker`, `dashboard`) execute as unprivileged user `zylaruser` (UID 10001, GID 10001). | **VERIFIED** in `tests/integration/test_compose_smoke.py` |

