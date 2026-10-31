# ADR-004: Deferring Distributed Message Brokers (Kafka) and Kubernetes

## Context and Problem Statement

When designing production-grade event-driven architectures, there is a strong temptation to introduce Apache Kafka (or RabbitMQ) for distributed event streaming and Kubernetes (K8s) for container orchestration.

For Zylar at its current operational scale ($10^3\text{–}10^5\text{ events/day}$, enterprise security team sizing of $1\text{–}10$ operators), adopting Kafka and Kubernetes introduces massive speculative complexity without providing tangible architectural benefits:
- Running Kafka requires ZooKeeper or KRaft consensus clusters, partition sizing, consumer group management, rebalance protocol tuning, and large memory baselines ($> 4\text{ GB}$).
- Running Kubernetes introduces Helm charts, ingress controllers, CSI volume drivers, network policies, and cluster maintenance burdens.
- Most importantly, distributed streaming brokers distribute state across nodes, making transactional idempotency and strict end-to-end ACID guarantees between stream offsets and incident databases exponentially harder to verify.

## Decision Drivers

- Maintain Zylar as a coherent, high-velocity **modular monolith**.
- Zero speculative complexity: avoid adding infrastructure components that cannot be justified by current telemetry.
- Single-command local repeatability: `docker compose up -d` must launch the entire verified stack on a standard workstation or modest cloud VM ($2\text{ vCPUs}, 8\text{ GB RAM}$).
- Verifiable transactional safety: Checkpoint advances, incident persistence, and audit records must commit inside single-database transactions.

## Considered Options

1. **Microservices on Kubernetes with Apache Kafka**: Decompose into 5 microservices communicating over Kafka topics, deployed via Helm on Kubernetes.
2. **Celery with Redis Broker**: Distributed task execution via Celery worker pools.
3. **Modular Monolith on Docker Compose with PostgreSQL Stream Checkpointing (Chosen)**: Retain shared Python domain packages, run distinct API and Worker container images via Docker Compose, and use PostgreSQL tables (`ingestion_checkpoints`, `dead_letter_events`) for streaming coordination.

## Decision Outcome

Chosen option: **Modular Monolith on Docker Compose (Option 3)**.

### Architectural Rules:
1. **Shared Domain Model**: All services (`api`, `worker`, `dashboard`) share typed domain models (`src/zylar/domain`), database entities (`src/zylar/persistence`), and analytics engines (`src/zylar/analysis`).
2. **PostgreSQL as Stream Checkpoint Engine**: Stream watermarking and lease acquisition are handled natively in PostgreSQL, eliminating the need for an external message broker.
3. **Container Orchestration via Docker Compose**: Service dependencies (`depends_on` with `service_healthy` and `service_completed_successfully`), network isolation (`zylar-backend`, `zylar-frontend`), and resource limits (`deploy.resources.limits`) are codified in `compose.yaml`.

### Migration Triggers (When to Revisit Kafka/K8s):
We will only consider migrating to Kafka and Kubernetes when:
- Ingestion sustained throughput exceeds $10,000\text{ events/second}$ across $> 50$ distinct concurrent stream partitions.
- Multi-region active-active cluster replication is mandated by enterprise compliance.
- Worker scaling requires dynamically auto-scaling across $> 20$ physical compute nodes.

### Consequences

#### Positive:
- Minimal resource footprint: Entire SOC stack runs smoothly on a single 8 GB host.
- Rapid developer velocity: Fast local debugging, test suite executes in $< 60\text{ seconds}$, zero cluster setup time.
- Transactional integrity: Atomic guarantees between stream checkpoints and incident persistence.

#### Negative:
- Vertical scaling ceiling: Worker throughput is bound by single-node PostgreSQL write and locking capacity (which easily supports $> 1,000\text{ events/sec}$, well above current requirements).

