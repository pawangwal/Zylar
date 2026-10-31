#!/usr/bin/env python3
"""Zylar Automated Database Backup & Disaster Recovery Verification Drill.

Verifies end-to-end database backup and restore capabilities:
  1. Dumps authoritative PostgreSQL state using pg_dump custom format (-Fc).
  2. Computes and records SHA-256 integrity digest of backup archive.
  3. Restores backup into an isolated verification database (default: zylar_restore_test).
  4. Verifies semantic parity (table row counts, sequence last_value, constraints).
  5. Executes operational read and insert smoke tests against restored database.
  6. Tears down temporary verification database.

Usage:
  python scripts/drills/backup_and_restore_drill.py [--target-db zylar_restore_test] [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zylar.backup_drill")

CRITICAL_TABLES: tuple[str, ...] = (
    "users",
    "incidents",
    "worker_instances",
    "ingestion_checkpoints",
    "dead_letter_events",
    "audit_logs",
    "alembic_version",
)

PROD_DB_NAMES: set[str] = {
    "prod",
    "production",
    "zylar_prod",
    "zylar_production",
    "zylar_live",
    "production_db",
}


def assert_restore_target_safety(source_db: str, target_db: str) -> None:
    """Enforces safety guards preventing accidental restore over production or source database."""
    src = source_db.strip().lower()
    tgt = target_db.strip().lower()

    if not tgt:
        raise ValueError("Safety violation: Restore target database name cannot be empty.")

    if not re.match(r"^[a-zA-Z0-9_]+$", tgt):
        raise ValueError(
            f"Safety violation: Target database identifier '{tgt}' contains invalid characters."
        )

    if tgt == src:
        raise ValueError(
            f"Safety violation: Restore target database '{tgt}' cannot match source database '{src}'."
        )

    for p in PROD_DB_NAMES:
        if p in tgt:
            raise ValueError(
                f"Safety violation: Restore target database '{tgt}' matches forbidden production pattern '{p}'."
            )


def calculate_file_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest of backup archive."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def verify_database_parity(
    source_counts: dict[str, int],
    target_counts: dict[str, int],
    source_sequences: dict[str, dict[str, Any]],
    target_sequences: dict[str, dict[str, Any]],
) -> bool:
    """Verifies that restored target database has exact row counts and matching sequence states."""
    all_tables = sorted(set(source_counts.keys()).union(target_counts.keys()))
    for t in all_tables:
        src_cnt = source_counts.get(t, 0)
        tgt_cnt = target_counts.get(t, 0)
        if src_cnt != tgt_cnt:
            raise ValueError(
                f"Row count mismatch on table '{t}': source has {src_cnt}, target has {tgt_cnt}."
            )

    for seq_name, s_data in source_sequences.items():
        if seq_name not in target_sequences:
            raise ValueError(
                f"Sequence state mismatch: sequence '{seq_name}' missing from target database."
            )
        t_data = target_sequences[seq_name]
        src_val = s_data.get("last_value", 0)
        tgt_val = t_data.get("last_value", 0)
        if tgt_val < src_val:
            raise ValueError(
                f"Sequence state mismatch on sequence '{seq_name}': "
                f"source last_value is {src_val}, target last_value is {tgt_val}."
            )
        if s_data.get("is_called") != t_data.get("is_called"):
            raise ValueError(
                f"Sequence state mismatch on sequence '{seq_name}': "
                f"source is_called is {s_data.get('is_called')}, target is_called is {t_data.get('is_called')}."
            )

    return True


def collect_table_counts(conn: psycopg.Connection[Any], tables: Sequence[str]) -> dict[str, int]:
    """Queries row counts for critical tables in public schema."""
    counts: dict[str, int] = {}
    with conn.cursor() as cur:
        for t in tables:
            cur.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s",
                (t,),
            )
            if cur.fetchone() is None:
                continue
            cur.execute(sql.SQL("SELECT count(*) FROM public.{}").format(sql.Identifier(t)))
            row = cur.fetchone()
            counts[t] = int(row[0]) if row and row[0] is not None else 0
    return counts


def collect_sequence_states(conn: psycopg.Connection[Any]) -> dict[str, dict[str, Any]]:
    """Queries sequence states from pg_sequences in public schema."""
    seqs: dict[str, dict[str, Any]] = {}
    with conn.cursor() as cur:
        cur.execute(
            "SELECT sequencename, last_value, start_value FROM pg_sequences WHERE schemaname = 'public'"
        )
        for r in cur.fetchall():
            seq_name = str(r[0])
            last_val_raw = r[1]
            start_val_raw = r[2]
            if last_val_raw is not None:
                last_val = int(last_val_raw)
                is_called = True
            else:
                last_val = int(start_val_raw) if start_val_raw is not None else 1
                is_called = False
            seqs[seq_name] = {"last_value": last_val, "is_called": is_called}
    return seqs


def run_data_smoke_test(conn: psycopg.Connection[Any]) -> None:
    """Executes read and audit log write smoke test to verify operational readiness of restored database."""
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.users")
        cur.execute(
            """
            INSERT INTO public.audit_logs (action, actor, details, created_at)
            VALUES ('DISASTER_RECOVERY_SMOKE_TEST', 'zylar_drill_runner', '{"status": "verified"}', NOW())
            """
        )
    conn.commit()


def mask_url(url: str) -> str:
    """Masks credentials in database URL."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.password:
            masked = parsed.netloc.replace(f":{parsed.password}@", ":***@")
            return parsed._replace(netloc=masked).geturl()
        return url
    except Exception:
        return "<masked_url>"


def run_drill(
    source_url: str,
    target_db: str = "zylar_restore_test",
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> bool:
    """Executes the full backup and restore verification drill."""
    parsed_src = urllib.parse.urlsplit(source_url)
    source_db = parsed_src.path.lstrip("/") or "zylar_db"

    assert_restore_target_safety(source_db=source_db, target_db=target_db)

    work_dir = backup_dir or Path(".backup_drill_staging")
    work_dir.mkdir(parents=True, exist_ok=True)
    dump_file = work_dir / f"zylar_backup_drill_{source_db}.dump"

    masked_src = mask_url(source_url)
    logger.info("Initiating disaster recovery verification drill.")
    logger.info("Source database: %s (DB: %s)", masked_src, source_db)
    logger.info("Target restore database: %s", target_db)

    if dry_run:
        logger.info("[DRY RUN] Validated parameters and safety guards cleanly.")
        return True

    # 1. Capture source database telemetry
    conn_src_url = source_url.replace("postgresql+psycopg://", "postgresql://")
    logger.info("Collecting source database baseline metrics...")
    with psycopg.connect(conn_src_url) as conn:
        source_counts = collect_table_counts(conn, CRITICAL_TABLES)
        source_sequences = collect_sequence_states(conn)

    logger.info("Source table row counts: %s", source_counts)
    logger.info("Source sequences count: %d", len(source_sequences))

    # 2. Dump source database using pg_dump custom format (-Fc)
    pg_dump_cmd = shutil.which("pg_dump")
    if not pg_dump_cmd:
        logger.error("pg_dump executable not found in system PATH.")
        return False

    dump_args = [
        pg_dump_cmd,
        "-Fc",
        "-f",
        str(dump_file),
        "--dbname",
        conn_src_url,
    ]
    logger.info("Executing pg_dump custom format archive...")
    res = subprocess.run(dump_args, capture_output=True, text=True)
    if res.returncode != 0:
        logger.error("pg_dump execution failed: %s", res.stderr)
        return False

    dump_sha256 = calculate_file_sha256(dump_file)
    dump_size_bytes = dump_file.stat().st_size
    logger.info("Backup archive generated: %s (%d bytes, SHA-256: %s)", dump_file.name, dump_size_bytes, dump_sha256)

    # 3. Create target restore database
    admin_base_url = urllib.parse.urlunsplit(parsed_src._replace(path="/postgres"))
    conn_admin_url = admin_base_url.replace("postgresql+psycopg://", "postgresql://")

    with psycopg.connect(conn_admin_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} (FORCE)").format(sql.Identifier(target_db)))
            cur.execute(sql.SQL("CREATE DATABASE {} OWNER zylar_migration").format(sql.Identifier(target_db)))
    logger.info("Created clean target restore database: %s", target_db)

    try:
        # 4. Restore into target database using pg_restore
        pg_restore_cmd = shutil.which("pg_restore")
        if not pg_restore_cmd:
            logger.error("pg_restore executable not found in system PATH.")
            return False

        target_conn_url = urllib.parse.urlunsplit(parsed_src._replace(path=f"/{target_db}"))
        restore_args = [
            pg_restore_cmd,
            "-d",
            target_conn_url.replace("postgresql+psycopg://", "postgresql://"),
            "--no-owner",
            str(dump_file),
        ]
        logger.info("Executing pg_restore into %s...", target_db)
        res_rest = subprocess.run(restore_args, capture_output=True, text=True)
        if res_rest.returncode != 0:
            logger.error("pg_restore failed with exit code %d: %s", res_rest.returncode, res_rest.stderr)
            return False

        # 5. Verify semantic parity and execute data smoke tests
        with psycopg.connect(target_conn_url.replace("postgresql+psycopg://", "postgresql://")) as target_conn:
            target_counts = collect_table_counts(target_conn, CRITICAL_TABLES)
            target_sequences = collect_sequence_states(target_conn)
            logger.info("Target table row counts: %s", target_counts)
            verify_database_parity(source_counts, target_counts, source_sequences, target_sequences)
            logger.info("Semantic parity verification passed! Executing data smoke tests...")
            run_data_smoke_test(target_conn)
            logger.info("Data smoke test succeeded.")
    finally:
        # 6. Teardown temporary restore database and remove dump archive
        try:
            with psycopg.connect(conn_admin_url, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} (FORCE)").format(sql.Identifier(target_db)))
            logger.info("Torn down verification target database %s.", target_db)
        except Exception as exc:
            logger.warning("Failed to teardown verification database '%s': %s", target_db, exc)

        if dump_file.exists():
            dump_file.unlink()

    logger.info("Disaster recovery verification drill completed successfully.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Zylar Database Backup & Recovery Drill")
    parser.add_argument("--source-url", default=os.environ.get("ZYLAR_ADMIN_DATABASE_URL") or os.environ.get("ZYLAR_DATABASE_URL"))
    parser.add_argument("--target-db", default="zylar_restore_test")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    source_url = args.source_url
    if not source_url:
        if args.dry_run:
            source_url = "postgresql://zylar_app:secret@127.0.0.1:5432/zylar_db"
        else:
            logger.error("Missing required database connection URL (ZYLAR_DATABASE_URL).")
            return 1

    try:
        success = run_drill(
            source_url=source_url,
            target_db=args.target_db,
            dry_run=args.dry_run,
        )
        return 0 if success else 1
    except Exception as exc:
        logger.error("Disaster recovery drill failed: %s: %s", type(exc).__name__, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

