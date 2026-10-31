# Elasticsearch Outage & Index Recovery Runbook

## 1. System Resilience & Decoupled State Architecture

Zylar is architected with strict persistence segregation:
- **PostgreSQL is the Authoritative Store**: All incident lifecycles, attack classifications, risk scores, users, and audit records reside in PostgreSQL.
- **Elasticsearch is the Search Engine**: Used for ingesting, indexing, and searching raw security event logs.

### Impact of Elasticsearch Outage
- **FastAPI Core Services**: Remain partially operational. Incidents can be inspected, reports downloaded, and user identity managed.
- **Health Probes**: `/health/ready` returns HTTP 503 (`elasticsearch: offline`), signalling load balancers to halt ingestion traffic.
- **Background Ingestion Worker**: Pauses log streaming and enters exponential backoff with jitter without corrupting checkpoints or losing PostgreSQL state.

---

## 2. Diagnosing Cluster Health & Connectivity

### 2.1 Cluster Health Probes

Query Elasticsearch cluster health via HTTPS:

```bash
curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
  "https://127.0.0.1:9200/_cluster/health?pretty"
```

Expected response status:
- `"green"`: All primary and replica shards allocated.
- `"yellow"`: All primary shards allocated, replica shards unassigned (normal for single-node development).
- `"red"`: One or more primary shards unassigned. Critical data unavailable.

### 2.2 Diagnosing Unassigned Shards

```bash
curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
  "https://127.0.0.1:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason"
```

### 2.3 Disk Space & Watermark Violations

Elasticsearch automatically blocks writes when disk usage exceeds the high watermark (default: 85% low, 90% high, 95% flood-stage):

```bash
curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
  "https://127.0.0.1:9200/_cat/allocation?v"
```

If flood-stage disk watermark was triggered, clear disk space and unlock index read-only blocks:

```bash
curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
  -X PUT "https://127.0.0.1:9200/_all/_settings" \
  -H "Content-Type: application/json" -d '{
    "index.blocks.read_only_allow_delete": null
  }'
```

---

## 3. Cluster Recovery & Restart Procedures

### 3.1 Restarting Container Instance

```bash
docker compose restart elasticsearch
```

Monitor container logs until the cluster reaches green or yellow state:

```bash
docker compose logs -f elasticsearch
```

### 3.2 Index Corruption or Re-Creation

If an index is hopelessly corrupted:
1. Delete corrupted index:
   ```bash
   curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
     -X DELETE "https://127.0.0.1:9200/security-events"
   ```
2. Re-create index with explicit mappings:
   ```bash
   curl -s -k -u "elastic:${ZYLAR_ELASTICSEARCH_PASSWORD}" \
     -X PUT "https://127.0.0.1:9200/security-events" \
     -H "Content-Type: application/json" -d '{
       "mappings": {
         "properties": {
           "event_id": {"type": "keyword"},
           "timestamp": {"type": "date"},
           "event_type": {"type": "keyword"},
           "source_ip": {"type": "ip"},
           "destination_port": {"type": "integer"},
           "user": {"type": "keyword"},
           "details": {"type": "text"}
         }
       }
     }'
   ```
3. Reset ingestion watermark in PostgreSQL to re-stream raw logs:
   ```sql
   UPDATE public.ingestion_checkpoints
   SET 
       last_processed_timestamp = '2026-10-30 00:00:00+00',
       last_processed_id = NULL,
       status = 'PENDING'
   WHERE stream_id = 'elasticsearch-soc-events';
   ```

