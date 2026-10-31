#!/usr/bin/env python3
"""Zylar PostgreSQL Role Provisioning & Object Ownership Setup Runner.

Executes scripts/sql/00_init_roles.sql against PostgreSQL using an administrative
connection, establishing least-privilege runtime roles and transferring object
ownership to zylar_migration.

Credentials:
  - Admin DB URL:            ZYLAR_ADMIN_DATABASE_URL or ZYLAR_DATABASE_URL
  - Migration Role Password: ZYLAR_MIGRATION_DB_PASSWORD
  - App Role Password:       ZYLAR_APP_DB_PASSWORD
  - Read-Only Role Password: ZYLAR_READ_DB_PASSWORD

Usage:
  python scripts/setup_postgres_roles.py [--dry-run]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import urllib.parse
import uuid
from pathlib import Path

import bcrypt
import psycopg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zylar.setup_roles")

SQL_FILE_PATH = Path(__file__).parent / "sql" / "00_init_roles.sql"
VALID_ENVIRONMENTS = {"development", "testing", "staging", "production"}
MIN_PASSWORD_LENGTH_PRODUCTION = 16
DISALLOWED_PASSWORD_PLACEHOLDERS = {
    "dev_migration_pass_123",
    "dev_app_pass_123",
    "dev_read_pass_123",
    "change-me",
    "password",
    "admin",
    "postgres",
    "root",
    "12345678",
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Idempotently provision Zylar database roles, object ownership, and least-privilege grants."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate parameters and parse SQL template without executing against the database.",
    )
    return parser.parse_args()


def mask_db_url(url: str) -> str:
    """Masks credentials in a database URL for safe logging."""
    try:
        parsed = urllib.parse.urlsplit(url)
        netloc = parsed.netloc
        if "@" in netloc:
            creds, hostport = netloc.split("@", 1)
            user = creds.split(":", 1)[0]
            masked_netloc = f"{user}:***@{hostport}"
        else:
            masked_netloc = netloc
        return urllib.parse.urlunsplit(
            (parsed.scheme, masked_netloc, parsed.path, parsed.query, parsed.fragment)
        )
    except Exception:
        return "[redacted-url]"


def get_required_credentials() -> tuple[str, str, str, str]:
    raw_env = os.environ.get("ZYLAR_ENVIRONMENT", "development").lower().strip()
    if raw_env not in VALID_ENVIRONMENTS:
        logger.error(
            "Invalid ZYLAR_ENVIRONMENT: '%s'. Allowed environments are: %s",
            raw_env,
            ", ".join(sorted(VALID_ENVIRONMENTS)),
        )
        sys.exit(1)

    admin_url = os.environ.get("ZYLAR_ADMIN_DATABASE_URL") or os.environ.get("ZYLAR_DATABASE_URL")
    if not admin_url:
        logger.error(
            "Missing admin connection string. Set ZYLAR_ADMIN_DATABASE_URL or ZYLAR_DATABASE_URL."
        )
        sys.exit(1)

    mig_pwd = os.environ.get("ZYLAR_MIGRATION_DB_PASSWORD") or (
        "dev_migration_pass_123" if raw_env in {"development", "testing"} else None
    )
    app_pwd = os.environ.get("ZYLAR_APP_DB_PASSWORD") or (
        "dev_app_pass_123" if raw_env in {"development", "testing"} else None
    )
    read_pwd = os.environ.get("ZYLAR_READ_DB_PASSWORD") or (
        "dev_read_pass_123" if raw_env in {"development", "testing"} else None
    )

    if raw_env in {"production", "staging"}:
        missing = []
        if not mig_pwd:
            missing.append("ZYLAR_MIGRATION_DB_PASSWORD")
        if not app_pwd:
            missing.append("ZYLAR_APP_DB_PASSWORD")
        if not read_pwd:
            missing.append("ZYLAR_READ_DB_PASSWORD")

        if missing:
            logger.error(
                "In %s environment, all role passwords must be explicitly set. Missing: %s",
                raw_env,
                ", ".join(missing),
            )
            sys.exit(1)

        assert mig_pwd is not None and app_pwd is not None and read_pwd is not None

        for name, val in [
            ("ZYLAR_MIGRATION_DB_PASSWORD", mig_pwd),
            ("ZYLAR_APP_DB_PASSWORD", app_pwd),
            ("ZYLAR_READ_DB_PASSWORD", read_pwd),
        ]:
            if val in DISALLOWED_PASSWORD_PLACEHOLDERS:
                logger.error(
                    "In %s environment, %s cannot be a default or placeholder value.", raw_env, name
                )
                sys.exit(1)
            if len(val) < MIN_PASSWORD_LENGTH_PRODUCTION:
                logger.error(
                    "In %s environment, %s must be at least %d characters (got %d).",
                    raw_env,
                    name,
                    MIN_PASSWORD_LENGTH_PRODUCTION,
                    len(val),
                )
                sys.exit(1)

        # Enforce distinct passwords between roles to maintain defense-in-depth isolation
        if len({mig_pwd, app_pwd, read_pwd}) != 3:
            logger.error(
                "In %s environment, zylar_migration, zylar_app, and zylar_read must use distinct passwords.",
                raw_env,
            )
            sys.exit(1)

    assert mig_pwd is not None and app_pwd is not None and read_pwd is not None
    return admin_url, mig_pwd, app_pwd, read_pwd


def sanitize_sql_string_literal(val: str) -> str:
    """Escapes single quotes for safe string literal interpolation into SQL statements."""
    return val.replace("'", "''")


def prepare_sql_script(sql_template: str, mig_pwd: str, app_pwd: str, read_pwd: str) -> str:
    """Replaces psql parameter placeholders with escaped password literals."""
    escaped_mig = f"'{sanitize_sql_string_literal(mig_pwd)}'"
    escaped_app = f"'{sanitize_sql_string_literal(app_pwd)}'"
    escaped_read = f"'{sanitize_sql_string_literal(read_pwd)}'"

    script = sql_template.replace(":'migration_password'", escaped_mig)
    script = script.replace(":'app_password'", escaped_app)
    script = script.replace(":'read_password'", escaped_read)
    return script


def main() -> int:
    args = parse_arguments()
    admin_url, mig_pwd, app_pwd, read_pwd = get_required_credentials()

    if not SQL_FILE_PATH.exists():
        logger.error("SQL script not found at %s", SQL_FILE_PATH)
        return 1

    sql_template = SQL_FILE_PATH.read_text(encoding="utf-8")
    prepared_sql = prepare_sql_script(sql_template, mig_pwd, app_pwd, read_pwd)

    raw_env = os.environ.get("ZYLAR_ENVIRONMENT", "development").lower().strip()
    masked_target = mask_db_url(admin_url)

    if args.dry_run:
        logger.info(
            "[DRY RUN] Mode active: Configuration and SQL template validated successfully without executing."
        )
        logger.info("[DRY RUN] Environment: %s", raw_env)
        logger.info("[DRY RUN] Target database: %s", masked_target)
        logger.info("[DRY RUN] Roles to provision: zylar_migration, zylar_app, zylar_read")
        logger.info("[DRY RUN] Prepared SQL length: %d bytes", len(prepared_sql))
        return 0

    # Convert SQLAlchemy psycopg URL scheme to standard libpq connection string if needed
    conn_url = admin_url.replace("postgresql+psycopg://", "postgresql://")

    logger.info("Connecting to PostgreSQL using administrative connection: %s", masked_target)
    try:
        with psycopg.connect(conn_url, autocommit=True) as conn:
            with conn.cursor() as cur:
                logger.info("Executing role setup, ownership transfer, and privilege grants...")
                cur.execute(prepared_sql)

                # Provision initial administrator under administrative credentials if table exists
                cur.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'"
                )
                if cur.fetchone():
                    admin_username = os.environ.get("ZYLAR_BOOTSTRAP_ADMIN_USERNAME", "admin").strip()
                    admin_password = os.environ.get(
                        "ZYLAR_BOOTSTRAP_ADMIN_PASSWORD", "change-admin-password-in-production"
                    ).strip()
                    cur.execute(
                        "SELECT 1 FROM public.users WHERE username = %s",
                        (admin_username,),
                    )
                    if not cur.fetchone():
                        salt = bcrypt.gensalt(rounds=12)
                        hashed_pwd = bcrypt.hashpw(admin_password.encode("utf-8"), salt).decode("utf-8")
                        cur.execute(
                            """
                            INSERT INTO public.users (id, username, hashed_password, role, disabled, created_at, updated_at)
                            VALUES (%s, %s, %s, 'admin', false, NOW(), NOW())
                            """,
                            (str(uuid.uuid4()), admin_username, hashed_pwd),
                        )
                        logger.info(
                            "Provisioned initial administrator account '%s' under administrative credentials.",
                            admin_username,
                        )
        logger.info(
            "Successfully provisioned roles (zylar_migration, zylar_app, zylar_read) and updated permissions."
        )
        return 0
    except psycopg.Error as exc:
        logger.error("PostgreSQL role setup failed: %s: %s", type(exc).__name__, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
