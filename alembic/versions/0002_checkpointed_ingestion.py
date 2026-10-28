"""Alembic migration for Phase 5 Checkpointed Ingestion and Dead-Letter Quarantining.

Revision ID: 0002_checkpointed_ingestion
Revises: 0001_initial_schema
Create Date: 2026-10-28 13:00:00+00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_checkpointed_ingestion"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Ingestion Checkpoints Table
    op.create_table(
        "ingestion_checkpoints",
        sa.Column("stream_id", sa.String(length=64), primary_key=True),
        sa.Column("last_processed_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_processed_id", sa.String(length=128), nullable=True),
        sa.Column(
            "batch_sequence",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "events_processed_count",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'IDLE'"),
        ),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "retry_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
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
            "retry_count >= 0",
            name="chk_ingestion_checkpoints_retry_nonneg",
        ),
        sa.CheckConstraint(
            "events_processed_count >= 0",
            name="chk_ingestion_checkpoints_count_nonneg",
        ),
        sa.CheckConstraint(
            "length(trim(stream_id)) > 0",
            name="chk_ingestion_checkpoints_stream_not_blank",
        ),
    )
    op.create_index(
        "ix_ingestion_checkpoints_last_processed_timestamp",
        "ingestion_checkpoints",
        ["last_processed_timestamp"],
    )

    # 2. Dead Letter Events Table
    op.create_table(
        "dead_letter_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("stream_id", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=True),
        sa.Column("raw_event_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "raw_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error_reason", sa.String(length=256), nullable=False),
        sa.Column("error_details", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'QUARANTINED'"),
        ),
        sa.Column(
            "quarantined_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "length(trim(stream_id)) > 0",
            name="chk_dead_letter_stream_not_blank",
        ),
        sa.CheckConstraint(
            "length(trim(raw_event_hash)) > 0",
            name="chk_dead_letter_hash_not_blank",
        ),
    )
    op.create_index(
        "ix_dead_letter_events_stream_id",
        "dead_letter_events",
        ["stream_id"],
    )
    op.create_index(
        "ix_dead_letter_events_event_id",
        "dead_letter_events",
        ["event_id"],
    )
    op.create_index(
        "ix_dead_letter_stream_quarantine",
        "dead_letter_events",
        ["stream_id", "quarantined_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_dead_letter_stream_quarantine", table_name="dead_letter_events")
    op.drop_index("ix_dead_letter_events_event_id", table_name="dead_letter_events")
    op.drop_index("ix_dead_letter_events_stream_id", table_name="dead_letter_events")
    op.drop_table("dead_letter_events")

    op.drop_index(
        "ix_ingestion_checkpoints_last_processed_timestamp",
        table_name="ingestion_checkpoints",
    )
    op.drop_table("ingestion_checkpoints")
