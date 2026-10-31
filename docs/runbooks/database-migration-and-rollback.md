# Database Migration & Rollback Runbook

## 1. Principles & Privilege Boundaries

Zylar uses Alembic for declarative, transactional schema migrations against PostgreSQL.

### Least-Privilege Role Separation
1. **`zylar_migration`**:
   - Schema owner (`public`) and owner of all tables and sequences.
   - Authorized to perform `CREATE`, `ALTER`, `DROP`, and DDL operations.
   - Used exclusively by the one-shot `migration` container during deployments and administrative CLI operations.
2. **`zylar_app`**:
   - Runtime application role for `api` and `worker`.
   - Table-specific DML only: `SELECT`, `INSERT`, `UPDATE`, `DELETE`.
   - Explicitly prohibited from DDL: cannot `DROP`, `TRUNCATE`, or `ALTER` tables.
   - Column-level insert restrictions on `users` prevent arbitrary privilege elevation.
3. **`zylar_read`**:
   - Read-only audit role (`SELECT` only, excluding sensitive credential columns).

---

## 2. Executing Schema Migrations

### 2.1 Standard Automated Deployment

In Docker Compose, migrations run automatically via the dedicated one-shot `migration` service before `api` or `worker` containers launch:

```bash
docker compose up migration
```

### 2.2 Manual Migration Execution via CLI

To manually apply pending migrations using administrative credentials:

```bash
# Export migration role database connection
export ZYLAR_DATABASE_URL="postgresql+psycopg://zylar_migration:${ZYLAR_MIGRATION_DB_PASSWORD}@127.0.0.1:5432/zylar_db"

# Check current revision
alembic current

# Check pending migrations
alembic history

# Upgrade to latest revision
alembic upgrade head
```

### 2.3 Post-Migration Privilege Refresh

Whenever a migration introduces new tables or sequences, run the role setup script to ensure least-privilege permissions are applied to `zylar_app` and `zylar_read`:

```bash
python scripts/setup_postgres_roles.py
```

---

## 3. Migration Rollback Procedure

### 3.1 Step 1: Pre-Rollback Impact Assessment

Before downgrading:
1. Identify the target revision:
   ```bash
   alembic history --verbose
   ```
2. Verify whether the downgrade script contains destructive drops (`DROP COLUMN`, `DROP TABLE`).
3. Ensure an immediate pre-rollback database backup is generated:
   ```bash
   pg_dump -U zylar_migration -d zylar_db -Fc -f "/var/backups/zylar/pre_rollback_$(date +%Y%m%d_%H%M%S).dump"
   ```

### 3.2 Step 2: Stop Application Runtime Services

To prevent lock contention or schema mismatches:

```bash
docker compose stop api worker
```

### 3.3 Step 3: Execute Downgrade

```bash
# Downgrade one revision
alembic downgrade -1

# Or downgrade to specific revision
alembic downgrade 0003_alembic_dead_letter_queue
```

### 3.4 Step 4: Verify Schema & Restart Services

```bash
# Verify current schema version
alembic current

# Restart runtime services
docker compose up -d api worker

# Verify service health
curl -f http://127.0.0.1:8000/api/health
```

---

## 4. Troubleshooting Common Failures

### Deadlock / Lock Timeout During Migration
If a migration hangs waiting for an `ACCESS EXCLUSIVE` lock on a table:
```sql
SELECT pid, query, age(clock_timestamp(), query_start), state
FROM pg_stat_activity
WHERE state != 'idle' AND pid <> pg_backend_pid();
```
Cancel the blocking background query or gracefully drain worker instances before retrying.

