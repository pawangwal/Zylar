from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all Zylar SQLAlchemy 2.0 models."""

    pass


class IncidentModel(Base):
    """Authoritative incident record persisted to PostgreSQL."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    attack_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_category: Mapped[str] = mapped_column(String(32), nullable=False)
    mitigation_plan: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    threat_intel: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    anomalous_events_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NEW", server_default=text("'NEW'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("id", uuid.uuid4())
        kwargs.setdefault("status", "NEW")
        kwargs.setdefault("anomalous_events_count", 0)
        kwargs.setdefault("mitigation_plan", [])
        kwargs.setdefault("threat_intel", {})
        super().__init__(**kwargs)

    event_refs: Mapped[list[IncidentEventRefModel]] = relationship(
        "IncidentEventRefModel", back_populates="incident", cascade="all, delete-orphan"
    )
    risk_records: Mapped[list[RiskHistoryModel]] = relationship(
        "RiskHistoryModel", back_populates="incident", cascade="all, delete-orphan"
    )
    audit_records: Mapped[list[AuditLogModel]] = relationship(
        "AuditLogModel", back_populates="incident"
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="chk_incidents_risk_score_range"),
        CheckConstraint("anomalous_events_count >= 0", name="chk_incidents_anomalous_events_nonneg"),
        CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE')",
            name="chk_incidents_valid_status",
        ),
        CheckConstraint("length(trim(incident_id)) > 0", name="chk_incidents_id_not_blank"),
        CheckConstraint(
            "length(trim(attack_classification)) > 0", name="chk_incidents_classification_not_blank"
        ),
        CheckConstraint("length(trim(risk_category)) > 0", name="chk_incidents_category_not_blank"),
        Index("ix_incidents_created_at", "created_at"),
        Index("ix_incidents_status_risk", "status", "risk_score"),
    )


class IncidentEventRefModel(Base):
    """References constituent events indexed in Elasticsearch without duplicating log bodies."""

    __tablename__ = "incident_event_refs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_identifier: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[IncidentModel] = relationship("IncidentModel", back_populates="event_refs")

    __table_args__ = (
        UniqueConstraint(
            "incident_id", "event_source", "source_event_id", name="uq_incident_source_event"
        ),
        Index("ix_event_ref_lookup", "event_source", "source_event_id"),
    )


class IPHistoryModel(Base):
    """Aggregate recurrence tracking for anomalous source IPs."""

    __tablename__ = "ip_history"

    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)
    offense_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("offense_count >= 0", name="chk_ip_history_offense_nonneg"),
        CheckConstraint(
            "last_risk_score >= 0 AND last_risk_score <= 100",
            name="chk_ip_history_last_risk_range",
        ),
        CheckConstraint("length(trim(ip_address)) > 0", name="chk_ip_history_address_not_blank"),
    )


class UserHistoryModel(Base):
    """Aggregate recurrence tracking for anomalous or compromised usernames."""

    __tablename__ = "user_history"

    username: Mapped[str] = mapped_column(String(128), primary_key=True)
    offense_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("offense_count >= 0", name="chk_user_history_offense_nonneg"),
        CheckConstraint(
            "last_risk_score >= 0 AND last_risk_score <= 100",
            name="chk_user_history_last_risk_range",
        ),
        CheckConstraint("length(trim(username)) > 0", name="chk_user_history_username_not_blank"),
    )


class RiskHistoryModel(Base):
    """Historical timeline of incident risk scores."""

    __tablename__ = "risk_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)

    incident: Mapped[IncidentModel] = relationship("IncidentModel", back_populates="risk_records")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="chk_risk_history_score_range"),
        Index("ix_risk_history_incident_time", "incident_id", "timestamp"),
    )


class AuditLogModel(Base):
    """Audit log capturing security-sensitive operations and state transitions."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    incident: Mapped[IncidentModel | None] = relationship(
        "IncidentModel", back_populates="audit_records"
    )

    __table_args__ = (
        CheckConstraint("length(trim(actor)) > 0", name="chk_audit_logs_actor_not_blank"),
        CheckConstraint("length(trim(action)) > 0", name="chk_audit_logs_action_not_blank"),
        CheckConstraint(
            "length(trim(correlation_id)) > 0", name="chk_audit_logs_correlation_not_blank"
        ),
    )


class IngestionCheckpointModel(Base):
    """Tracks persistent ingestion watermarks, batch sequence, and worker lease state."""

    __tablename__ = "ingestion_checkpoints"

    stream_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_processed_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_processed_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    batch_sequence: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    events_processed_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="IDLE", server_default=text("'IDLE'")
    )
    lease_owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("retry_count >= 0", name="chk_ingestion_checkpoints_retry_nonneg"),
        CheckConstraint("events_processed_count >= 0", name="chk_ingestion_checkpoints_count_nonneg"),
        CheckConstraint("length(trim(stream_id)) > 0", name="chk_ingestion_checkpoints_stream_not_blank"),
    )


class DeadLetterEventModel(Base):
    """Quarantines permanently invalid or poison events without halting ingestion batches."""

    __tablename__ = "dead_letter_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    stream_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    raw_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    error_reason: Mapped[str] = mapped_column(String(256), nullable=False)
    error_details: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="QUARANTINED", server_default=text("'QUARANTINED'")
    )
    quarantined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("length(trim(stream_id)) > 0", name="chk_dead_letter_stream_not_blank"),
        CheckConstraint("length(trim(raw_event_hash)) > 0", name="chk_dead_letter_hash_not_blank"),
        Index("ix_dead_letter_stream_quarantine", "stream_id", "quarantined_at"),
    )
