from __future__ import annotations

import logging

import pytest
from scripts.setup_postgres_roles import (
    SQL_FILE_PATH,
    get_required_credentials,
    logger,
    main,
    mask_db_url,
    prepare_sql_script,
    sanitize_sql_string_literal,
)


def test_sql_file_exists_and_contains_expected_blocks():
    """The 00_init_roles.sql script must exist and enforce least privilege, dynamic DB, and column restrictions."""
    assert SQL_FILE_PATH.exists(), f"SQL file not found at {SQL_FILE_PATH}"
    content = SQL_FILE_PATH.read_text(encoding="utf-8")

    # 1. Idempotent role creation
    assert "CREATE ROLE zylar_migration" in content
    assert "CREATE ROLE zylar_app" in content
    assert "CREATE ROLE zylar_read" in content
    assert "ALTER ROLE zylar_migration WITH PASSWORD :'migration_password';" in content
    assert "ALTER ROLE zylar_app WITH PASSWORD :'app_password';" in content
    assert "ALTER ROLE zylar_read WITH PASSWORD :'read_password';" in content

    # 2. Dynamic database connection grants (no hardcoded zylar_db)
    assert "zylar_db" not in content, "Database name must not be hardcoded to zylar_db"
    assert "current_database()" in content
    assert (
        "EXECUTE format('GRANT CONNECT ON DATABASE %I TO zylar_migration', current_database());"
        in content
    )
    assert (
        "EXECUTE format('GRANT CONNECT ON DATABASE %I TO zylar_app', current_database());"
        in content
    )
    assert (
        "EXECUTE format('GRANT CONNECT ON DATABASE %I TO zylar_read', current_database());"
        in content
    )

    # 3. Ownership transfer covering tables, sequences, views, matviews, routines (unambiguous arguments)
    assert "ALTER SCHEMA public OWNER TO zylar_migration;" in content
    assert "information_schema.sequences" in content
    assert "information_schema.views" in content
    assert "pg_matviews" in content
    assert "pg_get_function_identity_arguments" in content
    assert "ALTER ROUTINE public.%I(%s) OWNER TO zylar_migration" in content

    # 4. Comprehensive privilege revocation
    assert "REVOKE ALL ON SCHEMA public FROM PUBLIC, zylar_app, zylar_read;" in content
    assert (
        "REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM PUBLIC, zylar_app, zylar_read;"
        in content
    )
    assert "ALTER DEFAULT PRIVILEGES FOR ROLE zylar_migration IN SCHEMA public" in content

    # 5. Table-specific least privilege for zylar_app
    assert "GRANT SELECT, INSERT ON TABLE public.audit_logs TO zylar_app" in content
    assert "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO zylar_app;" in content
    assert "GRANT UPDATE ON ALL SEQUENCES" not in content, (
        "Sequences must not grant UPDATE to runtime app"
    )

    # 6. Column-level user insert restriction: role column must be excluded
    assert (
        "GRANT INSERT (id, username, hashed_password, disabled, created_at, updated_at) ON TABLE public.users TO zylar_app"
        in content
    )
    assert "GRANT UPDATE (disabled, updated_at) ON TABLE public.users TO zylar_app" in content
    # Ensure there is no unconditional whole-table INSERT on users
    assert "GRANT SELECT, INSERT ON TABLE public.users TO zylar_app" not in content

    # 7. Sensitive data protection: users_public_view excludes hashed_password
    assert "users_public_view" in content
    assert (
        "SELECT id, username, role, disabled, created_at, updated_at FROM public.users" in content
    )
    assert "REVOKE ALL ON TABLE public.users FROM zylar_read" in content


def test_sanitize_sql_string_literal():
    """Quotes in passwords must be doubled to prevent SQL injection."""
    raw = "pass'word''with'quotes"
    sanitized = sanitize_sql_string_literal(raw)
    assert sanitized == "pass''word''''with''quotes"


def test_prepare_sql_script_substitutes_placeholders():
    """Placeholders must be cleanly replaced with properly quoted literals."""
    template = "MIG=:'migration_password'; APP=:'app_password'; READ=:'read_password';"
    prepared = prepare_sql_script(template, "mig_pass", "app_pass", "read_pass")
    assert prepared == "MIG='mig_pass'; APP='app_pass'; READ='read_pass';"


def test_mask_db_url():
    """mask_db_url redacts the password portion while keeping user and host intact."""
    url = "postgresql://zylar_admin:secret_pass_12345@db.internal:5432/zylar_prod"
    masked = mask_db_url(url)
    assert "secret_pass_12345" not in masked
    assert masked == "postgresql://zylar_admin:***@db.internal:5432/zylar_prod"


def test_get_required_credentials_environment_validation(monkeypatch: pytest.MonkeyPatch):
    """Unknown environment must cause an immediate exit."""
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "invalid_env_name")
    with pytest.raises(SystemExit):
        get_required_credentials()


def test_get_required_credentials_production_validation_missing_passwords(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production mode must reject missing explicit passwords."""
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "ZYLAR_ADMIN_DATABASE_URL", "postgresql://admin:admin12345678@127.0.0.1:5432/zylar_db"
    )
    monkeypatch.delenv("ZYLAR_MIGRATION_DB_PASSWORD", raising=False)
    monkeypatch.delenv("ZYLAR_APP_DB_PASSWORD", raising=False)
    monkeypatch.delenv("ZYLAR_READ_DB_PASSWORD", raising=False)

    with pytest.raises(SystemExit):
        get_required_credentials()


def test_get_required_credentials_production_validation_placeholders(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production mode must reject placeholder passwords."""
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "ZYLAR_ADMIN_DATABASE_URL", "postgresql://admin:admin12345678@127.0.0.1:5432/zylar_db"
    )
    monkeypatch.setenv("ZYLAR_MIGRATION_DB_PASSWORD", "dev_migration_pass_123")
    monkeypatch.setenv("ZYLAR_APP_DB_PASSWORD", "valid_app_password_987654321")
    monkeypatch.setenv("ZYLAR_READ_DB_PASSWORD", "valid_read_password_987654321")

    with pytest.raises(SystemExit):
        get_required_credentials()


def test_get_required_credentials_production_validation_short_passwords(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production mode must reject passwords shorter than 16 characters."""
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "ZYLAR_ADMIN_DATABASE_URL", "postgresql://admin:admin12345678@127.0.0.1:5432/zylar_db"
    )
    monkeypatch.setenv("ZYLAR_MIGRATION_DB_PASSWORD", "short_mig_pass")  # 14 chars
    monkeypatch.setenv("ZYLAR_APP_DB_PASSWORD", "valid_app_password_987654321")
    monkeypatch.setenv("ZYLAR_READ_DB_PASSWORD", "valid_read_password_987654321")

    with pytest.raises(SystemExit):
        get_required_credentials()


def test_get_required_credentials_production_validation_non_distinct(
    monkeypatch: pytest.MonkeyPatch,
):
    """Production mode must reject identical passwords between different roles."""
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "ZYLAR_ADMIN_DATABASE_URL", "postgresql://admin:admin12345678@127.0.0.1:5432/zylar_db"
    )
    same_pass = "super_secure_shared_password_12345"
    monkeypatch.setenv("ZYLAR_MIGRATION_DB_PASSWORD", same_pass)
    monkeypatch.setenv("ZYLAR_APP_DB_PASSWORD", same_pass)
    monkeypatch.setenv("ZYLAR_READ_DB_PASSWORD", "super_secure_distinct_pass_67890")

    with pytest.raises(SystemExit):
        get_required_credentials()


def test_get_required_credentials_production_validation_success(monkeypatch: pytest.MonkeyPatch):
    """Production mode succeeds with distinct, non-placeholder >= 16 char passwords."""
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "ZYLAR_ADMIN_DATABASE_URL", "postgresql://admin:admin12345678@127.0.0.1:5432/zylar_db"
    )
    monkeypatch.setenv("ZYLAR_MIGRATION_DB_PASSWORD", "super_secure_mig_password_12345")
    monkeypatch.setenv("ZYLAR_APP_DB_PASSWORD", "super_secure_app_password_12345")
    monkeypatch.setenv("ZYLAR_READ_DB_PASSWORD", "super_secure_read_password_12345")

    admin_url, mig, app, read = get_required_credentials()
    assert admin_url == "postgresql://admin:admin12345678@127.0.0.1:5432/zylar_db"
    assert mig == "super_secure_mig_password_12345"
    assert app == "super_secure_app_password_12345"
    assert read == "super_secure_read_password_12345"


def test_dry_run_execution(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    """Dry run validates template and configuration without connecting to DB."""
    logger.disabled = False
    logger.setLevel(logging.INFO)
    logger.propagate = True
    caplog.set_level(logging.INFO, logger="zylar.setup_roles")
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "development")
    monkeypatch.setenv(
        "ZYLAR_ADMIN_DATABASE_URL", "postgresql://admin:secret@127.0.0.1:5432/zylar_db"
    )
    monkeypatch.setattr("sys.argv", ["setup_postgres_roles.py", "--dry-run"])

    exit_code = main()
    assert exit_code == 0
    assert "[DRY RUN] Mode active" in caplog.text
    assert "secret" not in caplog.text  # Password must be masked in log
