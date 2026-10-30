from __future__ import annotations

import urllib.parse
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from zylar.core.settings import get_settings

ALEMBIC_INI_PATH = Path(__file__).resolve().parents[2] / "alembic.ini"


def check_live_postgres() -> bool:
    settings = get_settings()
    try:
        engine = create_engine(str(settings.database_url), connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not check_live_postgres(),
    reason="PostgreSQL not reachable at configured ZYLAR_DATABASE_URL",
)


@pytest.fixture
def disposable_test_db():
    """Provisions an isolated, disposable PostgreSQL database for migration lifecycle testing.

    Guarantees that downgrade/re-upgrade tests never touch, downgrade, or drop
    schema objects in the main development/production database (zylar_db).
    """
    settings = get_settings()
    parsed = urllib.parse.urlsplit(str(settings.database_url))
    maint_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, "/postgres", parsed.query, parsed.fragment)
    )
    test_db_name = f"zylar_test_mig_{uuid.uuid4().hex[:8]}"
    test_db_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"/{test_db_name}", parsed.query, parsed.fragment)
    )

    maint_engine = create_engine(maint_url, isolation_level="AUTOCOMMIT")
    with maint_engine.connect() as conn:
        conn.execute(text(f"CREATE DATABASE {test_db_name}"))

    test_engine = create_engine(test_db_url)
    cfg = Config(str(ALEMBIC_INI_PATH))
    cfg.set_main_option("sqlalchemy.url", test_db_url)

    try:
        yield test_engine, cfg
    finally:
        test_engine.dispose()
        with maint_engine.connect() as conn:
            conn.execute(
                text(
                    f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    f"WHERE datname = '{test_db_name}' AND pid <> pg_backend_pid()"
                )
            )
            conn.execute(text(f"DROP DATABASE IF EXISTS {test_db_name}"))
        maint_engine.dispose()


def test_alembic_migration_lifecycle(disposable_test_db):
    """Tests upgrade to head, verifies schema, tests constraints, downgrades to base, and re-upgrades.

    Runs entirely within an ephemeral, disposable database to protect real data.
    """
    engine, alembic_config = disposable_test_db

    # 1. Run migration upgrade head
    command.upgrade(alembic_config, "head")

    # 2. Inspect created tables
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    expected = {
        "incidents",
        "incident_event_refs",
        "ip_history",
        "user_history",
        "risk_history",
        "audit_logs",
        "ingestion_checkpoints",
        "dead_letter_events",
        "users",
        "worker_instances",
    }
    assert expected.issubset(tables)

    # 3. Test check constraints against live PostgreSQL
    with engine.connect() as conn:
        # Constraint test: invalid risk score (> 100)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO incidents (
                            incident_id, idempotency_key, timestamp, attack_classification,
                            risk_score, risk_category, status
                        ) VALUES (
                            'ZYLAR-INC-TEST-INVALID', 'req:test-invalid-score', NOW(), 'Test',
                            150, 'Critical', 'NEW'
                        )
                        """
                    )
                )

        # Constraint test: invalid status value
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO incidents (
                            incident_id, idempotency_key, timestamp, attack_classification,
                            risk_score, risk_category, status
                        ) VALUES (
                            'ZYLAR-INC-TEST-INVALID-STATUS', 'req:test-invalid-status', NOW(), 'Test',
                            50, 'Medium', 'UNKNOWN_STATUS'
                        )
                        """
                    )
                )

        # Constraint test: blank incident_id
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO incidents (
                            incident_id, idempotency_key, timestamp, attack_classification,
                            risk_score, risk_category, status
                        ) VALUES (
                            '   ', 'req:test-blank-id', NOW(), 'Test',
                            50, 'Medium', 'NEW'
                        )
                        """
                    )
                )

        # Constraint test: blank checkpoint stream_id
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO ingestion_checkpoints (
                            stream_id, last_processed_timestamp
                        ) VALUES (
                            '   ', NOW()
                        )
                        """
                    )
                )

        # Constraint test: negative checkpoint retry_count
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO ingestion_checkpoints (
                            stream_id, last_processed_timestamp, retry_count
                        ) VALUES (
                            'valid-stream', NOW(), -1
                        )
                        """
                    )
                )

        # Constraint test: invalid checkpoint status (chk_checkpoint_status)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO ingestion_checkpoints (
                            stream_id, last_processed_timestamp, status
                        ) VALUES (
                            'valid-stream-invalid-status', NOW(), 'INVALID_STATUS'
                        )
                        """
                    )
                )

        # Constraint test: negative checkpoint batch_sequence (chk_batch_sequence_nonneg)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO ingestion_checkpoints (
                            stream_id, last_processed_timestamp, batch_sequence
                        ) VALUES (
                            'valid-stream-neg-seq', NOW(), -1
                        )
                        """
                    )
                )

        # Constraint test: negative checkpoint lease_generation (chk_lease_generation_nonneg)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO ingestion_checkpoints (
                            stream_id, last_processed_timestamp, lease_generation
                        ) VALUES (
                            'valid-stream-neg-gen', NOW(), -1
                        )
                        """
                    )
                )

        # Constraint test: blank dead letter hash
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO dead_letter_events (
                            stream_id, raw_event_hash, error_reason
                        ) VALUES (
                            'valid-stream', '   ', 'bad format'
                        )
                        """
                    )
                )

        # Constraint test: invalid dead letter status (chk_dead_letter_status)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO dead_letter_events (
                            stream_id, raw_event_hash, error_reason, status
                        ) VALUES (
                            'valid-stream', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'bad format', 'INVALID_DLQ_STATUS'
                        )
                        """
                    )
                )

        # Valid insert on dead_letter_events
        with conn.begin():
            conn.execute(
                text(
                    """
                    INSERT INTO dead_letter_events (
                        stream_id, event_id, raw_event_hash, error_reason, status
                    ) VALUES (
                        'stream-dlq-1', 'evt-poison-1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'malformed', 'QUARANTINED'
                    )
                    """
                )
            )

        # Unique constraint test: duplicate (stream_id, event_id) on dead_letter_events (uq_dead_letter_stream_event)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO dead_letter_events (
                            stream_id, event_id, raw_event_hash, error_reason, status
                        ) VALUES (
                            'stream-dlq-1', 'evt-poison-1', 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', 'duplicate poison', 'QUARANTINED'
                        )
                        """
                    )
                )

        # Valid insert and uniqueness test
        with conn.begin():
            conn.execute(
                text(
                    """
                    INSERT INTO incidents (
                        incident_id, idempotency_key, timestamp, attack_classification,
                        risk_score, risk_category, status
                    ) VALUES (
                        'ZYLAR-INC-TEST-VALID-1', 'req:test-unique-key-1', NOW(), 'Port Scan',
                        45, 'Medium', 'NEW'
                    )
                    """
                )
            )

        # Duplicate idempotency_key rejection
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO incidents (
                            incident_id, idempotency_key, timestamp, attack_classification,
                            risk_score, risk_category, status
                        ) VALUES (
                            'ZYLAR-INC-TEST-VALID-2', 'req:test-unique-key-1', NOW(), 'Port Scan',
                            45, 'Medium', 'NEW'
                        )
                        """
                    )
                )

        # Constraint test: users invalid role (chk_users_role)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO users (
                            username, hashed_password, role
                        ) VALUES (
                            'bad_role_user', 'hash123', 'superuser'
                        )
                        """
                    )
                )

        # Constraint test: users blank username (chk_users_username_not_blank)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO users (
                            username, hashed_password, role
                        ) VALUES (
                            '   ', 'hash123', 'analyst'
                        )
                        """
                    )
                )

        # Constraint test: worker_instances invalid status (chk_worker_status)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO worker_instances (
                            worker_instance_id, worker_name, hostname, status
                        ) VALUES (
                            'w-bad-status', 'ingest', 'host1', 'BOGUS_STATUS'
                        )
                        """
                    )
                )

        # Constraint test: worker_instances blank worker_name (chk_worker_name_not_blank)
        with pytest.raises((IntegrityError, DBAPIError)):
            with conn.begin():
                conn.execute(
                    text(
                        """
                        INSERT INTO worker_instances (
                            worker_instance_id, worker_name, hostname, status
                        ) VALUES (
                            'w-blank-name', '   ', 'host1', 'ACTIVE'
                        )
                        """
                    )
                )

    # 4. Test intermediate downgrade to 0002_checkpointed_ingestion
    command.downgrade(alembic_config, "0002_checkpointed_ingestion")
    inspector_post_0002 = inspect(engine)
    cp_cols_0002 = {c["name"] for c in inspector_post_0002.get_columns("ingestion_checkpoints")}
    assert "lease_generation" not in cp_cols_0002
    assert "next_retry_at" not in cp_cols_0002

    # 5. Test clean downgrade to base
    command.downgrade(alembic_config, "base")
    inspector_post_downgrade = inspect(engine)
    remaining_tables = set(inspector_post_downgrade.get_table_names())
    assert expected.isdisjoint(remaining_tables)

    # 6. Test clean re-upgrade to head
    command.upgrade(alembic_config, "head")
    inspector_reupgrade = inspect(engine)
    reup_tables = set(inspector_reupgrade.get_table_names())
    assert expected.issubset(reup_tables)
    cp_cols_reup = {c["name"] for c in inspector_reupgrade.get_columns("ingestion_checkpoints")}
    assert "lease_generation" in cp_cols_reup
    assert "next_retry_at" in cp_cols_reup
