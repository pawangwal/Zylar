from __future__ import annotations

import urllib.parse
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from scripts.setup_postgres_roles import SQL_FILE_PATH, prepare_sql_script
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

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
def disposable_roles_test_db():
    """Provisions a disposable database to test role setup and privileges against live PostgreSQL."""
    settings = get_settings()
    parsed = urllib.parse.urlsplit(str(settings.database_url))
    maint_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, "/postgres", parsed.query, parsed.fragment)
    )
    test_db_name = f"zylar_test_roles_{uuid.uuid4().hex[:8]}"
    test_db_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"/{test_db_name}", parsed.query, parsed.fragment)
    )

    maint_engine = create_engine(maint_url, isolation_level="AUTOCOMMIT")
    with maint_engine.connect() as conn:
        conn.execute(text(f"CREATE DATABASE {test_db_name}"))

    mig_pass = f"test_mig_pass_{uuid.uuid4().hex}"
    app_pass = f"test_app_pass_{uuid.uuid4().hex}"
    read_pass = f"test_read_pass_{uuid.uuid4().hex}"

    # Run Alembic migrations against the disposable database first
    cfg = Config(str(ALEMBIC_INI_PATH))
    cfg.set_main_option("sqlalchemy.url", test_db_url)
    command.upgrade(cfg, "head")

    # Run role setup script against the disposable database
    sql_template = SQL_FILE_PATH.read_text(encoding="utf-8")
    prepared_sql = prepare_sql_script(sql_template, mig_pass, app_pass, read_pass)

    admin_engine = create_engine(test_db_url, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        conn.execute(text(prepared_sql))
    admin_engine.dispose()

    mig_netloc = f"zylar_migration:{mig_pass}@{parsed.hostname}:{parsed.port or 5432}"
    mig_url = urllib.parse.urlunsplit(
        (parsed.scheme, mig_netloc, f"/{test_db_name}", parsed.query, parsed.fragment)
    )

    app_netloc = f"zylar_app:{app_pass}@{parsed.hostname}:{parsed.port or 5432}"
    app_url = urllib.parse.urlunsplit(
        (parsed.scheme, app_netloc, f"/{test_db_name}", parsed.query, parsed.fragment)
    )

    read_netloc = f"zylar_read:{read_pass}@{parsed.hostname}:{parsed.port or 5432}"
    read_url = urllib.parse.urlunsplit(
        (parsed.scheme, read_netloc, f"/{test_db_name}", parsed.query, parsed.fragment)
    )

    yield {
        "db_name": test_db_name,
        "admin_url": test_db_url,
        "mig_url": mig_url,
        "app_url": app_url,
        "read_url": read_url,
        "mig_pass": mig_pass,
        "app_pass": app_pass,
        "read_pass": read_pass,
    }

    # Teardown: terminate active connections and drop disposable test database
    with maint_engine.connect() as conn:
        conn.execute(
            text(
                f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{test_db_name}' AND pid <> pg_backend_pid()"
            )
        )
        conn.execute(text(f"DROP DATABASE IF EXISTS {test_db_name}"))
    maint_engine.dispose()


def test_postgres_role_privileges_matrix(disposable_roles_test_db):
    """Verifies that zylar_app and zylar_read strictly adhere to least privilege boundaries."""
    app_url = disposable_roles_test_db["app_url"]
    read_url = disposable_roles_test_db["read_url"]

    app_engine = create_engine(app_url)
    read_engine = create_engine(read_url)

    # 1. zylar_app cannot drop tables or execute DDL
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(text("DROP TABLE incidents"))
    assert (
        "must be owner" in str(exc_info.value).lower()
        or "permission denied" in str(exc_info.value).lower()
    )

    # 2. zylar_app cannot truncate tables
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(text("TRUNCATE TABLE incidents"))
    assert "permission denied" in str(exc_info.value).lower()

    # 3. zylar_app cannot delete from operational tables
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(text("DELETE FROM incidents WHERE 1=1"))
    assert "permission denied" in str(exc_info.value).lower()

    # 4. zylar_app cannot update audit_logs (append-only)
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(text("UPDATE audit_logs SET action = 'tampered'"))
    assert "permission denied" in str(exc_info.value).lower()

    # 5. zylar_app cannot create new tables in public schema
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(text("CREATE TABLE evil_table (id INT)"))
    assert "permission denied" in str(exc_info.value).lower()

    # 6. zylar_read cannot insert, update, or delete
    with pytest.raises(DBAPIError) as exc_info:
        with read_engine.begin() as conn:
            conn.execute(text("DELETE FROM incidents WHERE 1=1"))
    assert "permission denied" in str(exc_info.value).lower()

    with pytest.raises(DBAPIError) as exc_info:
        with read_engine.begin() as conn:
            conn.execute(text("UPDATE incidents SET status = 'closed'"))
    assert "permission denied" in str(exc_info.value).lower()

    with pytest.raises(DBAPIError) as exc_info:
        with read_engine.begin() as conn:
            conn.execute(text("INSERT INTO audit_logs (id, action) VALUES (99999, 'evil')"))
    assert "permission denied" in str(exc_info.value).lower()

    # 7. zylar_read can query operational tables
    with read_engine.begin() as conn:
        result = conn.execute(text("SELECT count(*) FROM incidents")).scalar()
        assert result == 0

    app_engine.dispose()
    read_engine.dispose()


def test_postgres_sequence_privileges(disposable_roles_test_db):
    """Verifies sequence USAGE is granted to zylar_app, but UPDATE (setval) is forbidden."""
    admin_url = disposable_roles_test_db["admin_url"]
    app_url = disposable_roles_test_db["app_url"]

    # As admin, create a sequence and transfer ownership to zylar_migration
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        conn.execute(text("CREATE SEQUENCE public.test_seq START 1;"))
        conn.execute(text("ALTER SEQUENCE public.test_seq OWNER TO zylar_migration;"))
        conn.execute(text("GRANT USAGE ON SEQUENCE public.test_seq TO zylar_app;"))
    admin_engine.dispose()

    app_engine = create_engine(app_url)
    with app_engine.begin() as conn:
        # nextval works with USAGE privilege
        val = conn.execute(text("SELECT nextval('public.test_seq')")).scalar()
        assert val == 1

        # setval requires UPDATE privilege and must fail
        with pytest.raises(DBAPIError) as exc_info:
            conn.execute(text("SELECT setval('public.test_seq', 100)"))
        assert "permission denied" in str(exc_info.value).lower()

    app_engine.dispose()


def test_users_table_column_restrictions_and_reconciler(disposable_roles_test_db):
    """Tests that re-running 00_init_roles.sql on newly created users table correctly enforces:
    1. zylar_app CANNOT insert into role column (preventing privilege escalation to admin).
    2. zylar_app CANNOT update role column.
    3. zylar_read CANNOT select from users table, only from users_public_view (no password hashes).
    """
    admin_url = disposable_roles_test_db["admin_url"]
    app_url = disposable_roles_test_db["app_url"]
    read_url = disposable_roles_test_db["read_url"]

    mig_pass = disposable_roles_test_db["mig_pass"]
    app_pass = disposable_roles_test_db["app_pass"]
    read_pass = disposable_roles_test_db["read_pass"]

    # 1. Re-run 00_init_roles.sql as reconciler to demonstrate reconciliation idempotency
    sql_template = SQL_FILE_PATH.read_text(encoding="utf-8")
    prepared_sql = prepare_sql_script(sql_template, mig_pass, app_pass, read_pass)
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        conn.execute(text(prepared_sql))
    admin_engine.dispose()

    app_engine = create_engine(app_url)
    read_engine = create_engine(read_url)

    # 3. zylar_app can insert user WITHOUT specifying role (default 'analyst' is assigned)
    user_id = str(uuid.uuid4())
    with app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO public.users (id, username, hashed_password, disabled) "
                "VALUES (:id, :username, :hashed_password, :disabled)"
            ),
            {
                "id": user_id,
                "username": "analyst_bob",
                "hashed_password": "hash123456",
                "disabled": False,
            },
        )

    # 4. zylar_app CANNOT insert user specifying role='admin'
    evil_id = str(uuid.uuid4())
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO public.users (id, username, hashed_password, role, disabled) "
                    "VALUES (:id, :username, :hashed_password, :role, :disabled)"
                ),
                {
                    "id": evil_id,
                    "username": "evil_admin",
                    "hashed_password": "hash123456",
                    "role": "admin",
                    "disabled": False,
                },
            )
    assert "permission denied" in str(exc_info.value).lower()

    # 5. zylar_app CANNOT update role column
    with pytest.raises(DBAPIError) as exc_info:
        with app_engine.begin() as conn:
            conn.execute(
                text("UPDATE public.users SET role = 'admin' WHERE id = :id"),
                {"id": user_id},
            )
    assert "permission denied" in str(exc_info.value).lower()

    # 6. zylar_app CAN update permitted non-privileged column (disabled)
    with app_engine.begin() as conn:
        conn.execute(
            text("UPDATE public.users SET disabled = TRUE WHERE id = :id"),
            {"id": user_id},
        )

    # 7. zylar_read CANNOT select directly from users table
    with pytest.raises(DBAPIError) as exc_info:
        with read_engine.begin() as conn:
            conn.execute(text("SELECT hashed_password FROM public.users"))
    assert "permission denied" in str(exc_info.value).lower()

    # 8. zylar_read CAN select from users_public_view and hashed_password is NOT exposed
    with read_engine.begin() as conn:
        row = (
            conn.execute(
                text("SELECT * FROM public.users_public_view WHERE id = :id"), {"id": user_id}
            )
            .mappings()
            .first()
        )
        assert row is not None
        assert row["username"] == "analyst_bob"
        assert row["role"] == "analyst"
        assert row["disabled"] is True
        assert "hashed_password" not in row

    app_engine.dispose()
    read_engine.dispose()
