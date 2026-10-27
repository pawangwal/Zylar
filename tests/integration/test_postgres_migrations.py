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

    # 4. Test clean downgrade
    command.downgrade(alembic_config, "base")
    inspector_post_downgrade = inspect(engine)
    remaining_tables = set(inspector_post_downgrade.get_table_names())
    assert expected.isdisjoint(remaining_tables)

    # 5. Test clean re-upgrade
    command.upgrade(alembic_config, "head")
    inspector_reupgrade = inspect(engine)
    reup_tables = set(inspector_reupgrade.get_table_names())
    assert expected.issubset(reup_tables)
