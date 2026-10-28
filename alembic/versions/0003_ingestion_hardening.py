"""Alembic migration for Phase 5 Checkpointed Ingestion Hardening.

Adds monotonic lease generation, next retry timestamp, status and sequence
check constraints, and dead-letter stream/event unique constraint.

Revision ID: 0003_ingestion_hardening
Revises: 0002_checkpointed_ingestion
Create Date: 2026-10-28 15:30:00+00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0003_ingestion_hardening"
down_revision: Union[str, None] = "0002_checkpointed_ingestion"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add lease_generation and next_retry_at to ingestion_checkpoints
    op.add_column(
        "ingestion_checkpoints",
        sa.Column(
            "lease_generation",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "ingestion_checkpoints",
        sa.Column(
            "next_retry_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # 2. Add check constraints to ingestion_checkpoints
    op.create_check_constraint(
        "chk_checkpoint_status",
        "ingestion_checkpoints",
        "status IN ('IDLE', 'PROCESSING', 'RETRYING', 'FAILED')",
    )
    op.create_check_constraint(
        "chk_batch_sequence_nonneg",
        "ingestion_checkpoints",
        "batch_sequence >= 0",
    )
    op.create_check_constraint(
        "chk_lease_generation_nonneg",
        "ingestion_checkpoints",
        "lease_generation >= 0",
    )

    # 3. Add check and unique constraints to dead_letter_events
    op.create_check_constraint(
        "chk_dead_letter_status",
        "dead_letter_events",
        "status IN ('QUARANTINED', 'REPROCESSED', 'DISCARDED')",
    )
    op.create_unique_constraint(
        "uq_dead_letter_stream_event",
        "dead_letter_events",
        ["stream_id", "event_id"],
    )


def downgrade() -> None:
    # 1. Drop constraints from dead_letter_events
    op.drop_constraint("uq_dead_letter_stream_event", "dead_letter_events", type_="unique")
    op.drop_constraint("chk_dead_letter_status", "dead_letter_events", type_="check")

    # 2. Drop constraints from ingestion_checkpoints
    op.drop_constraint("chk_lease_generation_nonneg", "ingestion_checkpoints", type_="check")
    op.drop_constraint("chk_batch_sequence_nonneg", "ingestion_checkpoints", type_="check")
    op.drop_constraint("chk_checkpoint_status", "ingestion_checkpoints", type_="check")

    # 3. Drop columns from ingestion_checkpoints
    op.drop_column("ingestion_checkpoints", "next_retry_at")
    op.drop_column("ingestion_checkpoints", "lease_generation")
