from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from zylar.persistence.dtos import IncidentCreate, PersistIncidentResult
from zylar.persistence.exceptions import (
    ConstraintViolationError,
    IdempotencyConflictError,
    PersistenceError,
    RecordNotFoundError,
)
from zylar.persistence.models import (
    AuditLogModel,
    IncidentEventRefModel,
    IncidentModel,
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
        """Retrieves an incident by its caller-supplied idempotency key."""
        stmt = select(IncidentModel).where(IncidentModel.idempotency_key == idempotency_key)
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
                f"'{existing.incident_id}' (payload mismatch: classification, risk score, or event count)."
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
                stmt = pg_insert(IPHistoryModel).values(
                    ip_address=ip,
                    offense_count=1,
                    last_seen=timestamp,
                    last_risk_score=risk_score,
                ).on_conflict_do_update(
                    index_elements=[IPHistoryModel.ip_address],
                    set_={
                        "offense_count": IPHistoryModel.offense_count + 1,
                        "last_seen": timestamp,
                        "last_risk_score": risk_score,
                        "updated_at": func.now(),
                    },
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
                stmt = pg_insert(UserHistoryModel).values(
                    username=user,
                    offense_count=1,
                    last_seen=timestamp,
                    last_risk_score=risk_score,
                ).on_conflict_do_update(
                    index_elements=[UserHistoryModel.username],
                    set_={
                        "offense_count": UserHistoryModel.offense_count + 1,
                        "last_seen": timestamp,
                        "last_risk_score": risk_score,
                        "updated_at": func.now(),
                    },
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
            select(IPHistoryModel.ip_address, IPHistoryModel.offense_count, IPHistoryModel.last_seen)
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
            select(UserHistoryModel.username, UserHistoryModel.offense_count, UserHistoryModel.last_seen)
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
