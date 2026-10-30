"""Alembic migration for Phase 7 Durable Identity and Worker Heartbeats.

Creates authoritative users table for durable authentication/RBAC and
worker_instances table for independent worker heartbeat tracking and telemetry.

Revision ID: 0004_identity_and_heartbeats
Revises: 0003_ingestion_hardening
Create Date: 2026-10-30 18:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic (must be <= 32 chars for alembic_version)
revision: str = "0004_identity_and_heartbeats"
down_revision: str | None = "0003_ingestion_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create users table
    op.create_table(
        "users",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("username", sa.String(128), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default=sa.text("'analyst'")),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
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
            "role IN ('admin', 'analyst', 'viewer')",
            name="chk_users_role",
        ),
        sa.CheckConstraint("length(trim(username)) > 0", name="chk_users_username_not_blank"),
        sa.CheckConstraint(
            "length(trim(hashed_password)) > 0", name="chk_users_hashed_password_not_blank"
        ),
    )
    op.create_index("ix_users_username", "users", ["username"])

    # 2. Create worker_instances table
    op.create_table(
        "worker_instances",
        sa.Column("worker_instance_id", sa.String(128), primary_key=True, nullable=False),
        sa.Column("worker_name", sa.String(128), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_successful_cycle_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failed_cycle_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'STARTING'"),
        ),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "status IN ('STARTING', 'ACTIVE', 'DEGRADED', 'STOPPING', 'STOPPED')",
            name="chk_worker_status",
        ),
        sa.CheckConstraint(
            "length(trim(worker_instance_id)) > 0", name="chk_worker_instance_id_not_blank"
        ),
        sa.CheckConstraint("length(trim(worker_name)) > 0", name="chk_worker_name_not_blank"),
    )
    op.create_index(
        "ix_worker_instances_name_heartbeat",
        "worker_instances",
        ["worker_name", "last_heartbeat_at"],
    )
    op.create_index(
        "ix_worker_instances_last_heartbeat",
        "worker_instances",
        ["last_heartbeat_at"],
    )

    # 3. PostgreSQL-specific view creation & permissions reconciliation
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("""
        DO $$
        BEGIN
          -- Create users_public_view excluding hashed_password
          CREATE OR REPLACE VIEW public.users_public_view AS
            SELECT id, username, role, disabled, created_at, updated_at FROM public.users;

          -- Assign view ownership to zylar_migration if role exists
          IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_migration') THEN
            ALTER TABLE public.users OWNER TO zylar_migration;
            ALTER TABLE public.worker_instances OWNER TO zylar_migration;
            ALTER VIEW public.users_public_view OWNER TO zylar_migration;
          END IF;

          -- Grant table-specific least privilege to zylar_app if role exists
          IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_app') THEN
            GRANT SELECT ON TABLE public.users TO zylar_app;
            GRANT INSERT (id, username, hashed_password, disabled, created_at, updated_at) ON TABLE public.users TO zylar_app;
            GRANT UPDATE (disabled, updated_at) ON TABLE public.users TO zylar_app;
            GRANT SELECT, INSERT, UPDATE ON TABLE public.worker_instances TO zylar_app;
          END IF;

          -- Grant read-only access to zylar_read if role exists
          IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'zylar_read') THEN
            GRANT SELECT ON TABLE public.users_public_view TO zylar_read;
            REVOKE ALL ON TABLE public.users FROM zylar_read;
            GRANT SELECT ON TABLE public.worker_instances TO zylar_read;
          END IF;
        END $$;
        """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP VIEW IF EXISTS public.users_public_view CASCADE;")

    op.drop_index("ix_worker_instances_last_heartbeat", table_name="worker_instances")
    op.drop_index("ix_worker_instances_name_heartbeat", table_name="worker_instances")
    op.drop_table("worker_instances")

    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
