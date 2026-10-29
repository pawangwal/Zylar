from __future__ import annotations

import hashlib
import json
import random
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload

from zylar.persistence.dtos import IncidentCreate, PersistIncidentResult
from zylar.persistence.exceptions import (
    ConstraintViolationError,
    IdempotencyConflictError,
    PersistenceError,
    RecordNotFoundError,
    StaleLeaseError,
)
from zylar.persistence.models import (
    AuditLogModel,
    DeadLetterEventModel,
    IncidentEventRefModel,
    IncidentModel,
    IngestionCheckpointModel,
    IPHistoryModel,
    RiskHistoryModel,
    UserHistoryModel,
)

VALID_STATUSES = frozenset(
    {"NEW", "TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED", "FALSE_POSITIVE"}
)


class IncidentRepository:
    """Repository managing incident records, event references, risk records, and audit logs.

    All operations operate on a caller-owned session and participate in the caller's transaction.
    This repository never commits or closes the session independently.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(self, incident_uuid: uuid.UUID) -> IncidentModel | None:
        """Retrieves an incident by its internal UUID primary key."""
        stmt = select(IncidentModel).where(IncidentModel.id == incident_uuid)
        return self._session.execute(stmt).scalar_one_or_none()

    def get_by_incident_id(self, incident_id: str) -> IncidentModel | None:
        """Retrieves an incident by its human-readable identifier (e.g. ZYLAR-INC-...)."""
        stmt = select(IncidentModel).where(IncidentModel.incident_id == incident_id)
        return self._session.execute(stmt).scalar_one_or_none()

    def get_by_idempotency_key(self, idempotency_key: str) -> IncidentModel | None:
        """Retrieves an incident by its caller-supplied idempotency key with constituent event references."""
        stmt = (
            select(IncidentModel)
            .options(selectinload(IncidentModel.event_refs))
            .where(IncidentModel.idempotency_key == idempotency_key)
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_incidents(
        self, limit: int = 50, offset: int = 0, status: str | None = None
    ) -> list[IncidentModel]:
        """Lists incidents ordered by creation time descending."""
        stmt = select(IncidentModel).order_by(IncidentModel.created_at.desc())
        if status is not None:
            stmt = stmt.where(IncidentModel.status == status)
        stmt = stmt.offset(offset).limit(limit)
        return list(self._session.execute(stmt).scalars().all())

    def create_incident(self, data: IncidentCreate) -> PersistIncidentResult:
        """Creates an incident and its related entities atomically within the caller's transaction.

        Guarantees idempotency:
        - If the idempotency key already exists and the payload matches, returns the existing record.
        - If the idempotency key already exists with a different payload, raises IdempotencyConflictError.
        - Handles concurrent insert races via savepoint rollback and post-conflict payload verification.
        """
        # 1. Pre-check for existing idempotency key
        existing = self.get_by_idempotency_key(data.idempotency_key)
        if existing is not None:
            if data.matches_existing(existing):
                return PersistIncidentResult(
                    incident=existing,
                    created=False,
                    idempotency_key=data.idempotency_key,
                )
            raise IdempotencyConflictError(
                f"Idempotency key '{data.idempotency_key}' conflicts with existing incident "
                f"'{existing.incident_id}' (payload mismatch: classification, risk score, mitigation plan, threat intel, or event references)."
            )

        # 2. Insert with savepoint to safely handle concurrent races without aborting the main transaction
        try:
            with self._session.begin_nested():
                incident = IncidentModel(
                    incident_id=data.incident_id,
                    idempotency_key=data.idempotency_key,
                    timestamp=data.timestamp,
                    attack_classification=data.attack_classification,
                    risk_score=data.risk_score,
                    risk_category=data.risk_category,
                    mitigation_plan=data.mitigation_plan,
                    threat_intel=data.threat_intel,
                    anomalous_events_count=data.anomalous_events_count,
                    status=data.status,
                )
                self._session.add(incident)
                self._session.flush()

                for ref in data.event_refs:
                    event_ref = IncidentEventRefModel(
                        incident_id=incident.id,
                        event_source=ref.event_source,
                        source_event_id=ref.source_event_id,
                        raw_event_hash=ref.raw_event_hash,
                        source_ip=ref.source_ip,
                        destination_port=ref.destination_port,
                        user_identifier=ref.user_identifier,
                        event_timestamp=ref.event_timestamp,
                    )
                    self._session.add(event_ref)

                risk_rec = RiskHistoryModel(
                    incident_id=incident.id,
                    timestamp=data.timestamp,
                    risk_score=data.risk_score,
                )
                self._session.add(risk_rec)

                audit_log = AuditLogModel(
                    actor=data.actor,
                    action="INCIDENT_CREATED",
                    incident_id=incident.id,
                    correlation_id=data.correlation_id or data.idempotency_key,
                    details={
                        "incident_id": incident.incident_id,
                        "classification": incident.attack_classification,
                        "risk_score": incident.risk_score,
                        "event_refs_count": len(data.event_refs),
                    },
                )
                self._session.add(audit_log)
                self._session.flush()

                return PersistIncidentResult(
                    incident=incident,
                    created=True,
                    idempotency_key=data.idempotency_key,
                )

        except IntegrityError as exc:
            err_str = str(exc).lower()
            # If the conflict is on the idempotency key (or incident_id in concurrent replays)
            if "idempotency_key" in err_str or "incident_id" in err_str:
                # Re-query the database for the conflicting record
                conflicting = self.get_by_idempotency_key(data.idempotency_key)
                if conflicting is not None:
                    if data.matches_existing(conflicting):
                        return PersistIncidentResult(
                            incident=conflicting,
                            created=False,
                            idempotency_key=data.idempotency_key,
                        )
                    raise IdempotencyConflictError(
                        f"Idempotency key '{data.idempotency_key}' conflicts with concurrently created incident "
                        f"'{conflicting.incident_id}' (payload mismatch)."
                    ) from exc

            # Distinguish check constraints or non-idempotency integrity violations
            raise ConstraintViolationError(
                f"Integrity constraint violation during incident creation: {exc.orig or exc}"
            ) from exc
        except DBAPIError as exc:
            raise PersistenceError(f"Database error during incident creation: {exc}") from exc

    def update_status(
        self,
        incident_id: str | uuid.UUID,
        new_status: str,
        actor: str,
        correlation_id: str,
        reason: str | None = None,
    ) -> IncidentModel:
        """Updates the status of an existing incident and records an audit log entry."""
        if new_status not in VALID_STATUSES:
            raise ConstraintViolationError(
                f"Invalid status '{new_status}'. Allowed values are: {sorted(VALID_STATUSES)}"
            )

        if isinstance(incident_id, uuid.UUID):
            incident = self.get_by_id(incident_id)
        else:
            incident = self.get_by_incident_id(incident_id)

        if incident is None:
            raise RecordNotFoundError(f"Incident '{incident_id}' not found.")

        old_status = incident.status
        incident.status = new_status
        incident.updated_at = datetime.now(UTC)

        audit_log = AuditLogModel(
            actor=actor,
            action="STATUS_CHANGE",
            incident_id=incident.id,
            correlation_id=correlation_id,
            details={
                "old_status": old_status,
                "new_status": new_status,
                "reason": reason or "",
            },
        )
        self._session.add(audit_log)
        self._session.flush()
        return incident


class OffenderHistoryRepository:
    """Repository managing IP and User recurrence history.

    Utilizes PostgreSQL atomic upserts (INSERT ... ON CONFLICT DO UPDATE) to prevent
    lost updates under concurrent write operations.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_ip_history(self, ip_address: str) -> IPHistoryModel | None:
        """Retrieves offense history for a single IP address."""
        stmt = select(IPHistoryModel).where(IPHistoryModel.ip_address == ip_address.strip())
        return self._session.execute(stmt).scalar_one_or_none()

    def get_user_history(self, username: str) -> UserHistoryModel | None:
        """Retrieves offense history for a single username."""
        stmt = select(UserHistoryModel).where(UserHistoryModel.username == username.strip())
        return self._session.execute(stmt).scalar_one_or_none()

    def get_recurrence_factor(self, ips: list[str], users: list[str]) -> int:
        """Calculates historical recurrence risk factor (0-100) based on accumulated offenses.

        Follows the Zylar SOC heuristic: 5 points per past offense, capped at 100.
        """
        clean_ips = [ip.strip() for ip in ips if ip and ip.strip()]
        clean_users = [u.strip() for u in users if u and u.strip()]

        total_offenses = 0

        if clean_ips:
            stmt = select(func.coalesce(func.sum(IPHistoryModel.offense_count), 0)).where(
                IPHistoryModel.ip_address.in_(clean_ips)
            )
            total_offenses += int(self._session.execute(stmt).scalar() or 0)

        if clean_users:
            stmt = select(func.coalesce(func.sum(UserHistoryModel.offense_count), 0)).where(
                UserHistoryModel.username.in_(clean_users)
            )
            total_offenses += int(self._session.execute(stmt).scalar() or 0)

        return min(100, total_offenses * 5)

    def record_offenses(
        self,
        ips: list[str],
        users: list[str],
        risk_score: int,
        timestamp: datetime,
    ) -> None:
        """Atomically increments offense counts and refreshes last seen timestamps.

        Safe against concurrent worker races.
        """
        clean_ips = [ip.strip() for ip in ips if ip and ip.strip()]
        clean_users = [u.strip() for u in users if u and u.strip()]

        # Check if running against PostgreSQL
        bind = self._session.bind
        is_pg = bind is not None and getattr(bind.dialect, "name", "") == "postgresql"

        for ip in clean_ips:
            if is_pg:
                stmt = (
                    pg_insert(IPHistoryModel)
                    .values(
                        ip_address=ip,
                        offense_count=1,
                        last_seen=timestamp,
                        last_risk_score=risk_score,
                    )
                    .on_conflict_do_update(
                        index_elements=[IPHistoryModel.ip_address],
                        set_={
                            "offense_count": IPHistoryModel.offense_count + 1,
                            "last_seen": timestamp,
                            "last_risk_score": risk_score,
                            "updated_at": func.now(),
                        },
                    )
                )
                self._session.execute(stmt)
            else:
                existing_ip = self.get_ip_history(ip)
                if existing_ip is not None:
                    existing_ip.offense_count += 1
                    existing_ip.last_seen = timestamp
                    existing_ip.last_risk_score = risk_score
                else:
                    self._session.add(
                        IPHistoryModel(
                            ip_address=ip,
                            offense_count=1,
                            last_seen=timestamp,
                            last_risk_score=risk_score,
                        )
                    )

        for user in clean_users:
            if is_pg:
                stmt = (
                    pg_insert(UserHistoryModel)
                    .values(
                        username=user,
                        offense_count=1,
                        last_seen=timestamp,
                        last_risk_score=risk_score,
                    )
                    .on_conflict_do_update(
                        index_elements=[UserHistoryModel.username],
                        set_={
                            "offense_count": UserHistoryModel.offense_count + 1,
                            "last_seen": timestamp,
                            "last_risk_score": risk_score,
                            "updated_at": func.now(),
                        },
                    )
                )
                self._session.execute(stmt)
            else:
                existing_user = self.get_user_history(user)
                if existing_user is not None:
                    existing_user.offense_count += 1
                    existing_user.last_seen = timestamp
                    existing_user.last_risk_score = risk_score
                else:
                    self._session.add(
                        UserHistoryModel(
                            username=user,
                            offense_count=1,
                            last_seen=timestamp,
                            last_risk_score=risk_score,
                        )
                    )

        self._session.flush()

    def get_top_offenders(self, limit: int = 5) -> dict[str, list[dict[str, Any]]]:
        """Retrieves the top recurring offending IPs and usernames ordered by offense count."""
        ip_stmt = (
            select(
                IPHistoryModel.ip_address, IPHistoryModel.offense_count, IPHistoryModel.last_seen
            )
            .order_by(IPHistoryModel.offense_count.desc())
            .limit(limit)
        )
        top_ips = [
            {
                "ip": row[0],
                "count": row[1],
                "last_seen": row[2].isoformat() if hasattr(row[2], "isoformat") else str(row[2]),
            }
            for row in self._session.execute(ip_stmt).all()
        ]

        user_stmt = (
            select(
                UserHistoryModel.username,
                UserHistoryModel.offense_count,
                UserHistoryModel.last_seen,
            )
            .order_by(UserHistoryModel.offense_count.desc())
            .limit(limit)
        )
        top_users = [
            {
                "user": row[0],
                "count": row[1],
                "last_seen": row[2].isoformat() if hasattr(row[2], "isoformat") else str(row[2]),
            }
            for row in self._session.execute(user_stmt).all()
        ]

        return {"top_ips": top_ips, "top_users": top_users}


MAX_DEAD_LETTER_PAYLOAD_BYTES = 64 * 1024  # 64 KiB (65,536 bytes)


class CheckpointRepository:
    """Repository managing persistent ingestion watermarks, lease state, and dead-letter quarantine."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, stream_id: str) -> IngestionCheckpointModel | None:
        """Retrieves a checkpoint by stream identifier."""
        stmt = select(IngestionCheckpointModel).where(
            IngestionCheckpointModel.stream_id == stream_id
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def get_or_create(
        self, stream_id: str, default_start_time: datetime
    ) -> IngestionCheckpointModel:
        """Retrieves an existing checkpoint or initializes a new one with the given default watermark."""
        cp = self.get(stream_id)
        if cp is not None:
            return cp

        cp = IngestionCheckpointModel(
            stream_id=stream_id,
            last_processed_timestamp=default_start_time,
            lease_generation=0,
            status="IDLE",
        )
        self._session.add(cp)
        self._session.flush()
        return cp

    def acquire_lease(
        self,
        stream_id: str,
        worker_id: str,
        lease_seconds: int = 60,
        default_start_time: datetime | None = None,
    ) -> tuple[bool, int]:
        """Atomically acquires an ingestion lease for worker_id.

        Returns (acquired, lease_generation).
        Enforces retry cooldown (next_retry_at), checks lease expiry,
        increments lease_generation monotonically, and sets status to 'PROCESSING'.
        """
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive.")

        now = datetime.now(UTC)
        start_time = default_start_time or now

        bind = None
        try:
            bind = self._session.get_bind()
        except Exception:
            pass
        is_pg = (
            bind is not None
            and getattr(bind, "dialect", None) is not None
            and bind.dialect.name == "postgresql"
        )

        if is_pg:
            # Conflict-safe initial checkpoint creation so SELECT ... FOR UPDATE always locks
            init_stmt = (
                pg_insert(IngestionCheckpointModel)
                .values(
                    stream_id=stream_id,
                    last_processed_timestamp=start_time,
                    status="IDLE",
                    lease_generation=0,
                    retry_count=0,
                    events_processed_count=0,
                    batch_sequence=0,
                )
                .on_conflict_do_nothing(index_elements=["stream_id"])
            )
            self._session.execute(init_stmt)

        stmt = (
            select(IngestionCheckpointModel)
            .where(IngestionCheckpointModel.stream_id == stream_id)
            .with_for_update()
        )
        checkpoint = self._session.execute(stmt).scalar_one_or_none()

        if checkpoint is None:
            # Fallback for non-PostgreSQL (e.g. SQLite / mock session)
            checkpoint = IngestionCheckpointModel(
                stream_id=stream_id,
                last_processed_timestamp=start_time,
                lease_owner=worker_id,
                lease_generation=1,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                status="PROCESSING",
            )
            self._session.add(checkpoint)
            self._session.flush()
            return True, 1

        # 1. Enforce scheduled retry cooldown deadline
        if checkpoint.next_retry_at is not None and checkpoint.next_retry_at > now:
            return False, checkpoint.lease_generation

        # 2. Check current lease ownership and active expiry
        if checkpoint.lease_owner is not None and checkpoint.lease_owner != worker_id:
            # Another worker has this lease.
            # Cannot acquire unless lease is explicitly expired.
            # Invariant 3: A missing lease expiry must not authorize stealing a lease with an owner.
            if checkpoint.lease_expires_at is None or checkpoint.lease_expires_at > now:
                return False, checkpoint.lease_generation

        # Eligible to acquire (new stream, owned by this worker, unowned, or previous lease expired)
        checkpoint.lease_generation = (checkpoint.lease_generation or 0) + 1
        checkpoint.lease_owner = worker_id
        checkpoint.lease_expires_at = now + timedelta(seconds=lease_seconds)
        checkpoint.status = "PROCESSING"
        checkpoint.updated_at = now
        self._session.flush()
        return True, checkpoint.lease_generation

    def renew_lease(
        self,
        stream_id: str,
        worker_id: str,
        lease_generation: int,
        lease_seconds: int = 60,
    ) -> bool:
        """Renews an active lease if still held by worker_id and matching lease_generation."""
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive.")

        stmt = (
            select(IngestionCheckpointModel)
            .where(IngestionCheckpointModel.stream_id == stream_id)
            .with_for_update()
        )
        checkpoint = self._session.execute(stmt).scalar_one_or_none()
        now = datetime.now(UTC)
        if (
            checkpoint is not None
            and checkpoint.lease_owner == worker_id
            and checkpoint.lease_generation == lease_generation
            and checkpoint.lease_expires_at is not None
            and checkpoint.lease_expires_at > now
        ):
            checkpoint.lease_expires_at = now + timedelta(seconds=lease_seconds)
            checkpoint.updated_at = now
            self._session.flush()
            return True
        return False

    def release_lease(
        self,
        stream_id: str,
        worker_id: str,
        lease_generation: int,
    ) -> bool:
        """Releases the lease if held by worker_id with matching lease_generation, transitioning to IDLE.

        Returns True if successfully released, False if lease was already lost or generation mismatched.
        """
        stmt = (
            select(IngestionCheckpointModel)
            .where(IngestionCheckpointModel.stream_id == stream_id)
            .with_for_update()
        )
        checkpoint = self._session.execute(stmt).scalar_one_or_none()
        now = datetime.now(UTC)
        if (
            checkpoint is not None
            and checkpoint.lease_owner == worker_id
            and checkpoint.lease_generation == lease_generation
        ):
            checkpoint.lease_owner = None
            checkpoint.lease_expires_at = None
            checkpoint.status = "IDLE"
            checkpoint.updated_at = now
            self._session.flush()
            return True
        return False

    def advance_checkpoint(
        self,
        stream_id: str,
        new_timestamp: datetime,
        last_id: str | None = None,
        processed_count: int = 0,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        lease_seconds: int = 60,
    ) -> IngestionCheckpointModel:
        """Advances the persistent checkpoint watermark and sequence.

        Validates that worker_id and lease_generation match the active lease row.
        Raises StaleLeaseError if the worker's fencing token is stale, missing, or expired.
        Resets retry_count and next_retry_at, and clears last_error upon durable progress.
        """
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive.")

        stmt = (
            select(IngestionCheckpointModel)
            .where(IngestionCheckpointModel.stream_id == stream_id)
            .with_for_update()
        )
        checkpoint = self._session.execute(stmt).scalar_one_or_none()
        if checkpoint is None:
            raise RecordNotFoundError(f"Checkpoint for stream '{stream_id}' does not exist.")

        now = datetime.now(UTC)

        # Validate fencing tokens
        if worker_id is None or lease_generation is None:
            raise StaleLeaseError(
                f"Cannot advance checkpoint for stream '{stream_id}': "
                "both worker_id and lease_generation are required fencing tokens."
            )

        if checkpoint.lease_owner != worker_id or checkpoint.lease_generation != lease_generation:
            raise StaleLeaseError(
                f"Stale lease for stream '{stream_id}': active owner is '{checkpoint.lease_owner}' "
                f"(generation {checkpoint.lease_generation}), but caller provided owner '{worker_id}' "
                f"(generation {lease_generation})."
            )

        if checkpoint.lease_expires_at is None or checkpoint.lease_expires_at <= now:
            expiry_str = (
                checkpoint.lease_expires_at.isoformat() if checkpoint.lease_expires_at else "None"
            )
            raise StaleLeaseError(
                f"Cannot advance checkpoint for stream '{stream_id}': "
                f"lease is missing or expired (expires_at={expiry_str}, current time {now.isoformat()})."
            )

        checkpoint.last_processed_timestamp = new_timestamp
        checkpoint.last_processed_id = last_id
        checkpoint.batch_sequence = (checkpoint.batch_sequence or 0) + 1
        checkpoint.events_processed_count = (checkpoint.events_processed_count or 0) + processed_count
        checkpoint.retry_count = 0
        checkpoint.next_retry_at = None
        checkpoint.last_error = None
        checkpoint.status = "PROCESSING"
        checkpoint.updated_at = now
        checkpoint.lease_expires_at = now + timedelta(seconds=lease_seconds)

        self._session.flush()
        return checkpoint

    def record_failure(
        self,
        stream_id: str,
        error: str,
        worker_id: str | None = None,
        lease_generation: int | None = None,
        max_retries: int = 5,
        backoff_initial_seconds: float = 2.0,
        backoff_factor: float = 2.0,
        backoff_max_seconds: float = 60.0,
        jitter_fn: Callable[[float], float] | None = None,
        now: datetime | None = None,
        backoff_seconds: float | None = None,
    ) -> IngestionCheckpointModel:
        """Records a batch ingestion failure, increments retry count, and schedules exponential backoff with jitter.

        Requires worker_id and lease_generation matching the active row.
        Raises StaleLeaseError if caller is stale or lease has expired.
        Clears lease ownership and expiration.
        If retry_count reaches max_retries, transitions to 'FAILED' with no next_retry_at.
        Otherwise transitions to 'RETRYING' and sets next_retry_at.
        """
        stmt = (
            select(IngestionCheckpointModel)
            .where(IngestionCheckpointModel.stream_id == stream_id)
            .with_for_update()
        )
        checkpoint = self._session.execute(stmt).scalar_one_or_none()
        if checkpoint is None:
            raise RecordNotFoundError(f"Checkpoint for stream '{stream_id}' does not exist.")

        current_now = now or datetime.now(UTC)

        # Validate fencing tokens
        if not worker_id or lease_generation is None:
            raise StaleLeaseError(
                f"Cannot record failure for stream '{stream_id}': "
                "both worker_id and lease_generation are required fencing tokens."
            )

        if checkpoint.lease_owner != worker_id or checkpoint.lease_generation != lease_generation:
            raise StaleLeaseError(
                f"Stale lease failure report for stream '{stream_id}': active owner is '{checkpoint.lease_owner}' "
                f"(generation {checkpoint.lease_generation}), but caller provided owner '{worker_id}' "
                f"(generation {lease_generation})."
            )

        if checkpoint.lease_expires_at is None or checkpoint.lease_expires_at <= current_now:
            expiry_str = (
                checkpoint.lease_expires_at.isoformat() if checkpoint.lease_expires_at else "None"
            )
            raise StaleLeaseError(
                f"Cannot record failure for stream '{stream_id}': "
                f"lease is missing or expired (expires_at={expiry_str}, current time {current_now.isoformat()})."
            )

        if backoff_seconds is not None:
            backoff_initial_seconds = float(backoff_seconds)

        checkpoint.retry_count += 1
        checkpoint.last_error = error
        checkpoint.lease_owner = None
        checkpoint.lease_expires_at = None
        checkpoint.updated_at = current_now

        if checkpoint.retry_count >= max_retries:
            checkpoint.status = "FAILED"
            checkpoint.next_retry_at = None
        else:
            checkpoint.status = "RETRYING"
            attempt = checkpoint.retry_count
            base_delay = min(
                backoff_max_seconds,
                backoff_initial_seconds * (backoff_factor ** (attempt - 1)),
            )
            if jitter_fn is not None:
                delay = jitter_fn(base_delay)
            else:
                jitter_factor = random.uniform(0.8, 1.2)
                delay = min(backoff_max_seconds, base_delay * jitter_factor)

            checkpoint.next_retry_at = current_now + timedelta(seconds=delay)

        self._session.flush()
        return checkpoint

    def quarantine_events(self, stream_id: str, dead_letters: list[dict[str, Any]]) -> int:
        """Persists unprocessable or malformed events into dead_letter_events idempotently.

        Enforces 64 KiB maximum payload size per event (evaluated in UTF-8 bytes).
        Uses PostgreSQL ON CONFLICT DO NOTHING for (stream_id, event_id) deduplication.
        Returns the count of newly inserted quarantine records.
        """
        if not dead_letters:
            return 0

        records_to_insert: list[dict[str, Any]] = []
        for item in dead_letters:
            raw_payload = item.get("raw_payload", {})
            if isinstance(raw_payload, bytes):
                payload_bytes = raw_payload
                try:
                    payload_dict = json.loads(raw_payload.decode("utf-8"))
                except Exception:
                    payload_dict = {"raw": raw_payload.decode("utf-8", errors="replace")}
            elif isinstance(raw_payload, str):
                payload_bytes = raw_payload.encode("utf-8")
                try:
                    payload_dict = json.loads(raw_payload)
                except Exception:
                    payload_dict = {"raw": raw_payload}
            else:
                payload_bytes = json.dumps(raw_payload, default=str).encode("utf-8")
                payload_dict = raw_payload

            if len(payload_bytes) > MAX_DEAD_LETTER_PAYLOAD_BYTES:
                event_id = item.get("event_id", "<unspecified>")
                raise ValueError(
                    f"Dead-letter payload for event '{event_id}' exceeds 64 KiB limit "
                    f"({len(payload_bytes)} bytes > {MAX_DEAD_LETTER_PAYLOAD_BYTES} bytes)."
                )

            raw_hash = item.get("raw_event_hash")
            if not raw_hash:
                raw_hash = hashlib.sha256(
                    json.dumps(payload_dict, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest()

            records_to_insert.append(
                {
                    "stream_id": stream_id,
                    "event_id": item.get("event_id"),
                    "raw_event_hash": raw_hash,
                    "raw_payload": payload_dict,
                    "error_reason": item.get("error_reason", "UNKNOWN_ERROR"),
                    "error_details": item.get("error_details"),
                    "status": item.get("status", "QUARANTINED"),
                }
            )

        bind = None
        try:
            bind = self._session.get_bind()
        except Exception:
            pass
        is_pg = (
            bind is not None
            and getattr(bind, "dialect", None) is not None
            and bind.dialect.name == "postgresql"
        )

        if is_pg:
            stmt = (
                pg_insert(DeadLetterEventModel)
                .values(records_to_insert)
                .on_conflict_do_nothing(index_elements=["stream_id", "event_id"])
                .returning(DeadLetterEventModel.id)
            )
            inserted_ids = self._session.execute(stmt).scalars().all()
            self._session.flush()
            return len(inserted_ids)

        # Dialect fallback (SQLite / Mock session)
        inserted_count = 0
        seen_in_batch: set[str] = set()
        for r in records_to_insert:
            evt_id = r.get("event_id")
            if evt_id is not None:
                if evt_id in seen_in_batch:
                    continue
                seen_in_batch.add(evt_id)
                exists = self._session.execute(
                    select(DeadLetterEventModel).where(
                        DeadLetterEventModel.stream_id == stream_id,
                        DeadLetterEventModel.event_id == evt_id,
                    )
                ).scalar_one_or_none()
                if exists is not None:
                    continue

            record = DeadLetterEventModel(**r)
            self._session.add(record)
            inserted_count += 1

        self._session.flush()
        return inserted_count

    def get_dead_letter_count(self, stream_id: str | None = None) -> int:
        """Returns the total number of quarantined dead-letter events."""
        stmt = select(func.count(DeadLetterEventModel.id))
        if stream_id is not None:
            stmt = stmt.where(DeadLetterEventModel.stream_id == stream_id)
        return int(self._session.execute(stmt).scalar() or 0)

    def get_checkpoint_lag_seconds(self, stream_id: str) -> float | None:
        """Returns elapsed seconds between now and the last processed watermark."""
        cp = self.get(stream_id)
        if cp is None:
            return None
        now = datetime.now(UTC)
        ts = cp.last_processed_timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return max(0.0, (now - ts).total_seconds())
