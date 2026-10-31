# Autonomous Worker Failover & Lifecycle Recovery Runbook

## 1. Architecture & Lifecycle Contracts

Zylar decouples the background ingestion worker (`python -m zylar.ingestion.runner`) from the FastAPI server into dedicated container processes.

### Core Contracts:
1. **Liveness & Telemetry**: Recorded in PostgreSQL `worker_instances` via periodic heartbeat (default: every 10 seconds).
2. **Stream Lease Ownership**: Managed exclusively in `ingestion_checkpoints` using optimistic concurrency leases (`lease_token` and `lease_generation` fencing tokens).
3. **Heartbeat vs Lease Separation**: A worker can be live (`status='ACTIVE'`) while not holding any stream lease, and an expired lease does not invalidate worker process liveness.
4. **Fencing Protection**: If an active worker cycle takes longer than `lease_duration_seconds` (30s) or loses its lease, the conditional SQL update detects `lease_generation` mismatch and raises `FencedLeaseError`, aborting the batch without committing partial state.

---

## 2. Health Monitoring & Failure Detection

### 2.1 Worker Telemetry & Lag Queries

Check active worker instances and heartbeat lag:

```sql
SELECT 
    worker_instance_id,
    worker_name,
    hostname,
    status,
    last_heartbeat_at,
    ROUND(EXTRACT(EPOCH FROM (NOW() - last_heartbeat_at))::numeric, 1) AS heartbeat_lag_seconds,
    ROUND(EXTRACT(EPOCH FROM (NOW() - last_successful_cycle_at))::numeric, 1) AS cycle_lag_seconds,
    last_error_code
FROM public.worker_instances
ORDER BY last_heartbeat_at DESC;
```

Check stream lease status and fencing tokens:

```sql
SELECT 
    stream_id,
    status,
    lease_owner,
    lease_generation,
    lease_expires_at,
    ROUND(EXTRACT(EPOCH FROM (lease_expires_at - NOW()))::numeric, 1) AS lease_remaining_seconds,
    retry_count,
    last_error
FROM public.ingestion_checkpoints;
```

### 2.2 Alert Thresholds

- **Heartbeat Lag Warning**: Heartbeat lag $> 30\text{ seconds}$ indicates worker process starvation, deadlock, or crash.
- **Heartbeat Lag Critical**: Heartbeat lag $> 60\text{ seconds}$ indicates worker process failure.
- **Lease Expiration**: When `NOW() > lease_expires_at`, any competing worker instance can acquire the lease and increment `lease_generation`.

---

## 3. Worker Troubleshooting & Recovery Procedures

### 3.1 Step 1: Inspect Worker Logs & Metrics

Query worker container logs and process-local Prometheus endpoint:

```bash
# Docker Compose logs
docker compose logs --tail=100 -f worker

# Query internal metrics endpoint (from inside backend network)
docker compose exec api curl -s http://worker:9102/metrics | grep zylar_
docker compose exec api curl -s http://worker:9102/healthz
```

### 3.2 Step 2: Restart Dead Worker Container

If the worker container is unresponsive or degraded:

```bash
# Restart worker container gracefully (Docker sends SIGTERM, waits 30s before SIGKILL)
docker compose restart worker
```

The worker catches `SIGTERM`, sets `self._is_draining = True`, completes any active cycle if lease is valid, transitions database status to `'STOPPED'`, and exits cleanly.

### 3.3 Step 3: Evicting a Stale Lease (Emergency Override)

If a crashed worker died without releasing its lease and immediate failover is required before automatic lease timeout:

```sql
UPDATE public.ingestion_checkpoints
SET 
    lease_owner = NULL,
    lease_expires_at = NOW() - INTERVAL '1 second',
    lease_generation = lease_generation + 1,
    status = 'PENDING',
    last_error = 'Operator manual lease revocation'
WHERE stream_id = 'elasticsearch-soc-events';
```

A surviving worker will immediately acquire the lease on its next polling tick with the new `lease_generation`.

