# Disaster Recovery & Database Backup Runbook

## 1. Executive Summary & SLO Objectives

Zylar operates as a mission-critical autonomous SOC system of record. System state is partitioned into two distinct persistence tiers:
1. **Authoritative Operational Store (PostgreSQL)**: Durable source of truth for incidents, stream ingestion watermarks, leases, worker heartbeats, users, roles, and compliance audit logs.
2. **Search & Log Store (Elasticsearch)**: Immutable append-only log index used for search queries and threat correlation.

### Recovery Objectives

| Metric | Target | Rationale |
| :--- | :--- | :--- |
| **RPO (PostgreSQL Logical Dumps)** | $\le 1\text{ hour}$ | Hourly full compressed custom-format dumps (`pg_dump -Fc`). |
| **RPO (PostgreSQL WAL Archiving)** | $\le 5\text{ minutes}$ | Continuous Write-Ahead Log archiving to remote object storage. |
| **RTO (PostgreSQL Restore)** | $\le 30\text{ minutes}$ | Automated scripted recovery with sequence validation. |
| **RPO (Elasticsearch Security Logs)** | $\le 24\text{ hours}$ | Search index reconstructible via log replay from cold store. |
| **RTO (Elasticsearch Cluster)** | $\le 60\text{ minutes}$ | Cluster rebuild and checkpoint watermark reset. |

---

## 2. PostgreSQL Backup Procedures

### 2.1 Daily & Hourly Automated Backups

Logical database backups are produced using PostgreSQL's custom binary format (`-Fc`), which includes built-in compression and granular table restoration capabilities.

```bash
# Set credentials
export PGPASSWORD="${ZYLAR_MIGRATION_DB_PASSWORD}"

# Execute custom-format backup
pg_dump -h 127.0.0.1 -p 5432 -U zylar_migration -d zylar_db \
  -Fc -Z 6 -f "/var/backups/zylar/zylar_db_$(date +%Y%m%d_%H%M%S).dump"

# Generate cryptographic checksum
sha256sum "/var/backups/zylar/zylar_db_$(date +%Y%m%d_%H%M%S).dump" > \
  "/var/backups/zylar/zylar_db_$(date +%Y%m%d_%H%M%S).dump.sha256"
```

### 2.2 Continuous Write-Ahead Log (WAL) Archiving

For high-availability environments requiring RPO $\le 5$ minutes, enable WAL archiving in `postgresql.conf`:

```ini
wal_level = replica
archive_mode = on
archive_command = 'test ! -f /mnt/wal_archive/%f && cp %p /mnt/wal_archive/%f'
archive_timeout = 300
```

---

## 3. Disaster Recovery Restoration Procedure

### 3.1 Step 1: Pre-Flight Safety Checks

Prior to restoring any backup archive, verify:
1. The target database does NOT equal the active production database without explicit administrative maintenance authorization.
2. The archive checksum matches the recorded SHA-256 digest:

```bash
sha256sum -c "/var/backups/zylar/zylar_db_20261031_000000.dump.sha256"
```

### 3.2 Step 2: Database Restoration Execution

```bash
# 1. Terminate existing client connections
psql -U postgres -d postgres -c "
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'zylar_db' AND pid <> pg_backend_pid();"

# 2. Re-create clean target database
psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS zylar_db (FORCE);"
psql -U postgres -d postgres -c "CREATE DATABASE zylar_db OWNER zylar_migration;"

# 3. Restore custom format archive
pg_restore -U zylar_migration -d zylar_db \
  --clean --if-exists --no-owner --role=zylar_migration \
  "/var/backups/zylar/zylar_db_20261031_000000.dump"
```

### 3.3 Step 3: Post-Restore Semantic Parity Verification

Verify all critical tables and sequence states:

```sql
-- Connect to restored database
\c zylar_db zylar_migration

-- 1. Check table row counts
SELECT 'incidents' AS tbl, count(*) FROM public.incidents
UNION ALL
SELECT 'users', count(*) FROM public.users
UNION ALL
SELECT 'ingestion_checkpoints', count(*) FROM public.ingestion_checkpoints
UNION ALL
SELECT 'dead_letter_events', count(*) FROM public.dead_letter_events;

-- 2. Verify sequence state exceeds current maximum ID
SELECT 
    s.sequencename, 
    s.last_value,
    CASE 
        WHEN s.sequencename = 'incidents_id_seq' THEN (SELECT COALESCE(max(id), 0) FROM public.incidents)
        WHEN s.sequencename = 'users_id_seq' THEN (SELECT COALESCE(max(id), 0) FROM public.users)
        ELSE 0 
    END AS max_table_id
FROM pg_sequences s
WHERE s.schemaname = 'public';
```

---

## 4. Automated Recovery Drill Runner

Zylar includes an automated disaster recovery drill runner that tests backup creation, checksumming, isolated database restoration, sequence validation, and transactional smoke tests.

```bash
# Execute drill against verification target
python scripts/drills/backup_and_restore_drill.py \
  --source-url "postgresql://postgres:postgres_dev_password_123@127.0.0.1:5432/zylar_db" \
  --target-db "zylar_restore_test"
```

The runner enforces strict safety guards:
- Rejects any restore attempt where the target matches the source.
- Rejects any restore target matching production keywords (`prod`, `production`, `zylar_live`).
- Tears down the verification database immediately upon completion.

---

## 5. Elasticsearch Incident Recovery & Checkpoint Reset

If Elasticsearch suffers total node failure or catastrophic data loss:
1. Re-provision the Elasticsearch container/cluster using Docker Compose.
2. The PostgreSQL operational store retains all historical incident records, risk scores, and mitigation plans intact.
3. To replay missed security events from cold storage or ingest pipeline:
   - Identify the earliest event timestamp available in cold storage.
   - Reset the stream ingestion checkpoint in PostgreSQL:

```sql
UPDATE public.ingestion_checkpoints
SET 
    last_processed_timestamp = '2026-10-30 00:00:00+00',
    last_processed_id = NULL,
    status = 'PENDING',
    retry_count = 0,
    last_error = 'Disaster recovery: Reset watermark for event replay'
WHERE stream_id = 'elasticsearch-soc-events';
```

4. The autonomous worker runner (`zylar.ingestion.runner`) will acquire a fresh lease and resume streaming from the specified watermark, reconstructing threat intelligence while deduplication guarantees prevent duplicate incident generation.

