# ADR-001: PostgreSQL and Elasticsearch Dual-Storage Architecture

## Context and Problem Statement

A security operations center (SOC) processes two fundamentally distinct classes of data:
1. High-volume, unstructured or semi-structured raw event logs arriving continuously from endpoints, network firewalls, and authentication services.
2. Authoritative operational state: security incidents, attack classifications, numerical risk scores, mitigation execution status, ingestion stream watermarks, optimistic leases, and audit logs.

Using a single persistence engine for both creates severe architectural compromises:
- Relational databases (e.g. PostgreSQL alone) struggle with high-throughput full-text querying, multi-field log aggregation, and unbounded JSON schema evolution.
- Document/search databases (e.g. Elasticsearch alone) lack ACID multi-row transactional guarantees, strong foreign key constraints, advisory locking, and deterministic isolation needed for authoritative incident records and checkpoint fencing.

## Decision Drivers

- Strong transactional guarantees (ACID) for incident tracking, deduplication, and stream watermark advancement.
- Fast full-text search, term filtering, and range indexing for millions of raw security logs.
- Clear persistence boundaries: operational state must remain intact and recoverable even if the raw log search cluster experiences catastrophic failure.
- Avoid architectural coupling where search engine degradation halts SOC incident investigations.

## Considered Options

1. **Pure PostgreSQL**: Store both raw logs and operational incidents in PostgreSQL (using JSONB and TimescaleDB).
2. **Pure Elasticsearch**: Store both raw logs and incident tracking records in Elasticsearch.
3. **Dual-Storage Architecture (PostgreSQL + Elasticsearch)**: PostgreSQL serves as the authoritative system of record; Elasticsearch serves as the search and log indexing engine.

## Decision Outcome

Chosen option: **Dual-Storage Architecture (Option 3)**.

### Storage Responsibilities:
- **PostgreSQL**: Authoritative System of Record. Owns `incidents`, `incident_source_ips`, `incident_user_identifiers`, `worker_instances`, `ingestion_checkpoints`, `dead_letter_events`, `users`, and `audit_logs`.
- **Elasticsearch**: Log Search Engine. Owns indices (`security-events-*`) containing raw logs.

### Consequences

#### Positive:
- Strong consistency: Incident creation, deduplication, and checkpoint advance execute inside atomic transactions (`UnitOfWork`).
- Resilient recovery: If Elasticsearch crashes or is corrupted, zero incidents or audit records are lost. Checkpoints can be reset to replay logs into a newly built index.
- Search performance: Sub-second search across security event logs without degrading PostgreSQL relational query throughput.

#### Negative:
- Operational overhead: Requires provisioning, monitoring, and backing up two distinct database systems.
- Data synchronization: The background ingestion worker must coordinate reading from Elasticsearch and writing commits to PostgreSQL with idempotent deduplication.

