"""Initial PostgreSQL persistence schema for Zylar.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-10-27 15:00:00+00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Incidents table
    op.create_table(
        "incidents",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("incident_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False, unique=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attack_classification", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_category", sa.String(length=32), nullable=False),
        sa.Column(
            "mitigation_plan",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "threat_intel",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "anomalous_events_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'NEW'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="chk_incidents_risk_score_range",
        ),
        sa.CheckConstraint(
            "anomalous_events_count >= 0",
            name="chk_incidents_anomalous_events_nonneg",
        ),
        sa.CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE')",
            name="chk_incidents_valid_status",
        ),
        sa.CheckConstraint(
            "length(trim(incident_id)) > 0",
            name="chk_incidents_id_not_blank",
        ),
        sa.CheckConstraint(
            "length(trim(attack_classification)) > 0",
            name="chk_incidents_classification_not_blank",
        ),
        sa.CheckConstraint(
            "length(trim(risk_category)) > 0",
            name="chk_incidents_category_not_blank",
        ),
    )
    op.create_index("ix_incidents_timestamp", "incidents", ["timestamp"], unique=False)
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"], unique=False)
    op.create_index("ix_incidents_status_risk", "incidents", ["status", "risk_score"], unique=False)

    # 2. Incident event references table
    op.create_table(
        "incident_event_refs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_source", sa.String(length=64), nullable=False),
        sa.Column("source_event_id", sa.String(length=128), nullable=False),
        sa.Column("raw_event_hash", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("user_identifier", sa.String(length=128), nullable=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "incident_id",
            "event_source",
            "source_event_id",
            name="uq_incident_source_event",
        ),
    )
    op.create_index(
        "ix_incident_event_refs_incident_id",
        "incident_event_refs",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        "ix_event_ref_lookup",
        "incident_event_refs",
        ["event_source", "source_event_id"],
        unique=False,
    )

    # 3. IP history table
    op.create_table(
        "ip_history",
        sa.Column("ip_address", sa.String(length=45), primary_key=True),
        sa.Column("offense_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_risk_score", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("offense_count >= 0", name="chk_ip_history_offense_nonneg"),
        sa.CheckConstraint(
            "last_risk_score >= 0 AND last_risk_score <= 100",
            name="chk_ip_history_last_risk_range",
        ),
        sa.CheckConstraint("length(trim(ip_address)) > 0", name="chk_ip_history_address_not_blank"),
    )

    # 4. User history table
    op.create_table(
        "user_history",
        sa.Column("username", sa.String(length=128), primary_key=True),
        sa.Column("offense_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_risk_score", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("offense_count >= 0", name="chk_user_history_offense_nonneg"),
        sa.CheckConstraint(
            "last_risk_score >= 0 AND last_risk_score <= 100",
            name="chk_user_history_last_risk_range",
        ),
        sa.CheckConstraint("length(trim(username)) > 0", name="chk_user_history_username_not_blank"),
    )

    # 5. Risk history table
    op.create_table(
        "risk_history",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="chk_risk_history_score_range",
        ),
    )
    op.create_index(
        "ix_risk_history_incident_time",
        "risk_history",
        ["incident_id", "timestamp"],
        unique=False,
    )

    # 6. Audit logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.CheckConstraint("length(trim(actor)) > 0", name="chk_audit_logs_actor_not_blank"),
        sa.CheckConstraint("length(trim(action)) > 0", name="chk_audit_logs_action_not_blank"),
        sa.CheckConstraint(
            "length(trim(correlation_id)) > 0", name="chk_audit_logs_correlation_not_blank"
        ),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
    op.create_index("ix_audit_logs_correlation_id", "audit_logs", ["correlation_id"], unique=False)
    op.create_index("ix_audit_logs_incident_id", "audit_logs", ["incident_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_logs_incident_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_correlation_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_risk_history_incident_time", table_name="risk_history")
    op.drop_table("risk_history")

    op.drop_table("user_history")
    op.drop_table("ip_history")

    op.drop_index("ix_event_ref_lookup", table_name="incident_event_refs")
    op.drop_index("ix_incident_event_refs_incident_id", table_name="incident_event_refs")
    op.drop_table("incident_event_refs")

    op.drop_index("ix_incidents_status_risk", table_name="incidents")
    op.drop_index("ix_incidents_created_at", table_name="incidents")
    op.drop_index("ix_incidents_timestamp", table_name="incidents")
    op.drop_table("incidents")
