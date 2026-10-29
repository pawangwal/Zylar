# Zylar Secrets Management and Security Policy

**Version:** 1.0  
**Effective Date:** 27 October 2026  
**Scope:** Development, Testing, CI/CD, and Production Deployments

---

## 1. Secrets Management Principles

Zylar enforces a strict separation between configuration, credentials, and source code. No secret or credential may enter source code, version control history, log messages, test fixtures, Docker build contexts, or distribution packages.

### Credential Classification and Placement

| Value | Local Development (`.env`) | GitHub Actions CI | Production Deployment | Source Code |
| --- | --- | --- | --- | --- |
| **PostgreSQL Password / Connection URL** | Local `.env` | Disposable CI Secret (`CI_POSTGRES_PASSWORD`, `CI_DATABASE_URL`) | Production Secrets Vault / Runtime Injection | **Never** |
| **JWT Signing Key (`ZYLAR_AUTH_SIGNING_KEY`)** | Local `.env` (randomly generated) | Disposable CI Secret if signing tests require | Key Management Service / Injected Secret | **Never** |
| **Bootstrap Admin Password (`ZYLAR_BOOTSTRAP_ADMIN_PASSWORD`)** | Local `.env` | Ephemeral test fixture account only | Securely bootstrapped / Injected Secret | **Never** |
| **Elasticsearch Credentials** | Local `.env` (if auth enabled) | Disposable CI Secret | Vault / Managed secret injection | **Never** |
| **Ollama URL & Model Name** | Configuration default / `.env` | Workflow Variable / `.env` | Environment Variable | Defaults permitted |
| **Public Service Hosts & Ports** | Configuration default / `.env` | Workflow Variable | Environment Variable | Defaults permitted |
| **Test Fixture Credentials** | In-memory dummy fixtures (`test_security.py`) | Ephemeral disposable accounts | Never used in production | Acceptable if unmistakably non-production |

> [!WARNING]
> A URL is not harmless configuration if it contains credentials. For example, `postgresql://user:password@host/db` contains a plaintext password and must be handled strictly as a secret.

---

## 2. Application-Level Security Controls

1. **Typed Settings (`src/zylar/core/settings.py`):**
   - All runtime settings are loaded exclusively through Pydantic BaseSettings with the `ZYLAR_` prefix. No ad-hoc `os.getenv()` calls are permitted across routes or agents.
2. **Fail-Fast Production Validation:**
   - In `production` environment (`ZYLAR_ENVIRONMENT=production`), the application strictly validates that:
     - `ZYLAR_AUTH_SIGNING_KEY` is not the default placeholder and is $\ge 32$ characters long.
     - `ZYLAR_BOOTSTRAP_ADMIN_PASSWORD` is not the default placeholder and is $\ge 12$ characters long.
     - `ZYLAR_DATABASE_URL` does not contain default placeholder credentials (`change-me`).
   - Startup aborts immediately with a `ValueError` if any placeholder is detected outside development.
3. **Diagnostic Redaction:**
   - Error handlers and logging pipelines must never output raw authentication headers, bearer tokens, full connection strings with passwords, or unsanitized payloads.
4. **Least-Privilege Docker Builds:**
   - `.dockerignore` excludes `.env`, `.venv`, `.git`, test databases, caches, and report files from entering container image layers.
5. **Elasticsearch Deployment Security Boundary:**
   - Development Compose (`elk_setup/docker-compose.yml`) binds ports strictly to `127.0.0.1` and disables X-Pack security for friction-free local iteration.
   - In production or shared infrastructure, disabling Elasticsearch security is strictly prohibited; deployments must enable X-Pack security, TLS on HTTP and transport layers, authenticate via `ZYLAR_ELASTICSEARCH_URL`, and isolate container networks.
6. **Reverse Proxy and IP Forwarding Trust Boundary:**
   - The API verifies `X-Forwarded-For` headers exclusively when the immediate connecting peer matches an IP in `ZYLAR_TRUSTED_PROXIES` (defaults to loopback `127.0.0.1`, `::1`). Untrusted connections use the socket peer IP, preventing client header spoofing.
7. **Thread-Safe Throttling & Sanitized Audit Logging:**
   - Authentication brute-force attempts are bounded by a thread-safe `LoginThrottler` using `threading.RLock()` and bounded memory pruning.
   - All audit log details are sanitized recursively (`sanitize_audit_details`) to strip credentials, tokens, and secrets before persistence.

---

## 3. Secret Rotation Procedures

### JWT Signing Key Rotation
1. Generate a new high-entropy 256-bit secret:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
2. Update the secret in the runtime environment / vault (`ZYLAR_AUTH_SIGNING_KEY`).
3. Note: Rotating the key immediately invalidates all active JWT tokens, requiring users and services to re-authenticate. (Key-ring rollover with dual-key validation may be introduced if zero-downtime rolling expiration is required in high-availability deployments).

### Database Credential Rotation
1. Provision the new password on the PostgreSQL database server.
2. Update the secret store or environment configuration with the updated `ZYLAR_DATABASE_URL`.
3. Restart or reload the application workers.
4. Revoke the prior database credential.

---

## 4. Leaked Credential Incident Response

If a credential is accidentally committed to Git or exposed:

1. **Immediate Revocation:** Revoke or change the compromised secret immediately at the identity provider, database, or signing authority. Do not wait for code removal.
2. **Remove and Replace:** Remove the credential from active configuration and update `.env` or CI secret settings with a freshly generated secret.
3. **History Purge:** If pushed to remote Git repositories, rewrite Git history using `git-filter-repo` or BFG Repo-Cleaner to scrub the commit, coordinate with collaborators, and force-push sanitized branches.
4. **Exposure Audit:** Inspect CI run logs, artifact registries, and access logs for the affected service during the window of exposure.

---

## 5. Security Acceptance Checklist

- [x] **No real credentials in tracked source files or test fixtures.** (Verified with `git grep` and `git ls-files`).
- [x] **`.env` is ignored and `.env.example` contains placeholders only.** (Verified in `.gitignore` and `.env.example`).
- [x] **No credentials embedded in Docker images or build artifacts.** (Enforced via `.dockerignore` and Hatch wheel exclusions).
- [x] **GitHub Actions uses least-privilege permissions and isolated CI credentials.** (Configured in `.github/workflows/ci.yml`).
- [x] **Application rejects placeholder secrets outside development.** (Automated in `Settings.validate_production_secrets` and tested in `test_settings.py`).
- [x] **Logs and error responses redact credentials and tokens.** (Enforced via `SafeErrorResponse` and correlation ID tracing).
- [ ] **PostgreSQL runtime and migration roles are separated in Phase 4.** (Targeted for Phase 4 database migration).
- [x] **Secret rotation and leaked-credential response are documented.** (Documented in this policy).
