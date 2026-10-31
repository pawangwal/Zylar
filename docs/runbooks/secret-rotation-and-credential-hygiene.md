# Secret Rotation & Credential Hygiene Runbook

## 1. Secret Inventory & Boundaries

Zylar enforces strict security policies across all deployment environments:
- Never commit secrets to version control.
- Never hardcode credentials in source code.
- Enforce minimum password lengths ($\ge 16$ characters in production).
- Disallow known default or placeholder passwords.
- Redact secrets from error logs, diagnostic endpoints, and HTTP responses.

### Secret Inventory

| Secret Variable | Usage | Rotation Frequency | Zero-Downtime Support |
| :--- | :--- | :--- | :--- |
| `ZYLAR_JWT_SECRET` | HMAC-SHA256 signature for user tokens | 90 days | Requires dual-key verification window |
| `ZYLAR_APP_DB_PASSWORD` | PostgreSQL DML runtime user (`zylar_app`) | 90 days | Supported via dual-role or reload |
| `ZYLAR_MIGRATION_DB_PASSWORD` | PostgreSQL DDL owner (`zylar_migration`) | 90 days | Supported (runs on deployment only) |
| `ZYLAR_READ_DB_PASSWORD` | Read-only audit user (`zylar_read`) | 90 days | Supported |
| `ZYLAR_ELASTICSEARCH_PASSWORD` | Elasticsearch basic authentication (`elastic`) | 90 days | Supported via Elasticsearch native API |
| `ZYLAR_BOOTSTRAP_ADMIN_PASSWORD` | Initial admin account creation | One-time | Disabled after initial admin bootstrap |

---

## 2. PostgreSQL Role Password Rotation

To rotate passwords without database service disruption:

### Step 1: Update Passwords in PostgreSQL

Connect as PostgreSQL administrative superuser:

```sql
-- Generate high-entropy 32-character random passwords
ALTER ROLE zylar_app WITH PASSWORD '<NEW_STRONG_APP_PASSWORD_32_CHARS>';
ALTER ROLE zylar_migration WITH PASSWORD '<NEW_STRONG_MIG_PASSWORD_32_CHARS>';
ALTER ROLE zylar_read WITH PASSWORD '<NEW_STRONG_READ_PASSWORD_32_CHARS>';
```

### Step 2: Update Environment Configuration

Update secrets in environment configuration or Docker Compose environment variables:

```bash
export ZYLAR_APP_DB_PASSWORD="<NEW_STRONG_APP_PASSWORD_32_CHARS>"
export ZYLAR_MIGRATION_DB_PASSWORD="<NEW_STRONG_MIG_PASSWORD_32_CHARS>"
export ZYLAR_READ_DB_PASSWORD="<NEW_STRONG_READ_PASSWORD_32_CHARS>"
```

### Step 3: Rolling Restart of Application Containers

Restart containers to pick up updated credentials:

```bash
docker compose up -d --no-deps api worker
```

Verify service connectivity:

```bash
curl -f http://127.0.0.1:8000/api/health/ready
```

---

## 3. JWT Secret Key Rotation

To rotate `ZYLAR_JWT_SECRET`:

1. Update `ZYLAR_JWT_SECRET` in environment variables.
2. Existing issued tokens will fail verification, requiring operators to re-authenticate with their credentials.
3. Verify that new tokens are issued with the updated signing key:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "<ADMIN_PASSWORD>"}'
   ```

---

## 4. Elasticsearch Password Rotation

To rotate `elastic` cluster superuser password:

```bash
# Update password in Elasticsearch native security backend
curl -s -k -u "elastic:${CURRENT_PASSWORD}" \
  -X POST "https://127.0.0.1:9200/_security/user/elastic/_password" \
  -H "Content-Type: application/json" -d '{
    "password": "<NEW_STRONG_ELASTIC_PASSWORD>"
  }'

# Update environment variable
export ZYLAR_ELASTICSEARCH_PASSWORD="<NEW_STRONG_ELASTIC_PASSWORD>"

# Restart API and Worker services
docker compose up -d --no-deps api worker
```

---

## 5. Security Audit Log Verification

Whenever credentials are changed, verify that all actions are audited without leaking raw secret strings:

```sql
SELECT action, actor, details, created_at
FROM public.audit_logs
ORDER BY created_at DESC
LIMIT 5;
```

Confirm that the `details` JSON field masks all password values with `***`.

