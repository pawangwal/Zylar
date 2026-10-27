from __future__ import annotations

import argparse
import json
import logging
import shutil
import sqlite3
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select, text

from zylar.core.logging import configure_logging
from zylar.core.settings import get_settings
from zylar.persistence.database import DatabaseManager
from zylar.persistence.models import (
    IncidentModel,
    IPHistoryModel,
    RiskHistoryModel,
    UserHistoryModel,
)

logger = logging.getLogger("zylar.migration")


def parse_iso_datetime(value: str | None) -> datetime:
    """Parses ISO timestamp strings into timezone-aware UTC datetime."""
    if not value:
        return datetime.now(UTC)
    clean_val = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(clean_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception:
        return datetime.now(UTC)


def backup_sqlite_database(sqlite_path: Path) -> Path:
    """Creates a timestamped backup of the source SQLite database."""
    backup_path = sqlite_path.with_suffix(f".db.bak_{int(datetime.now(UTC).timestamp())}")
    shutil.copy2(sqlite_path, backup_path)
    # Also maintain a standard .db.bak copy
    standard_bak = sqlite_path.with_suffix(".db.bak")
    shutil.copy2(sqlite_path, standard_bak)
    logger.info("Backed up SQLite database to %s and %s", backup_path, standard_bak)
    return standard_bak


def migrate_sqlite_to_postgres(
    sqlite_path: Path,
    db_manager: DatabaseManager,
    dry_run: bool = False,
    backup: bool = True,
) -> dict[str, Any]:
    """Migrates historical SOC state from SQLite to PostgreSQL with dual-count verification."""
    if not sqlite_path.exists():
        raise FileNotFoundError(f"Source SQLite database not found at {sqlite_path}")

    if backup and not dry_run:
        backup_sqlite_database(sqlite_path)

    conn = sqlite3.connect(str(sqlite_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Fetch raw SQLite records
    incidents_raw = cursor.execute("SELECT * FROM incidents").fetchall()
    ip_raw = cursor.execute("SELECT * FROM ip_history").fetchall()
    user_raw = cursor.execute("SELECT * FROM user_history").fetchall()
    risk_raw = cursor.execute("SELECT * FROM risk_history").fetchall()
    conn.close()

    logger.info(
        "Extracted from SQLite: %d incidents, %d IP records, %d user records, %d risk records",
        len(incidents_raw),
        len(ip_raw),
        len(user_raw),
        len(risk_raw),
    )

    stats: dict[str, int] = {
        "sqlite_incidents": len(incidents_raw),
        "sqlite_ip_history": len(ip_raw),
        "sqlite_user_history": len(user_raw),
        "sqlite_risk_history": len(risk_raw),
        "migrated_incidents": 0,
        "migrated_ip_history": 0,
        "migrated_user_history": 0,
        "migrated_risk_history": 0,
    }

    if dry_run:
        logger.info("Dry-run mode active. No changes committed to PostgreSQL.")
        return stats

    with db_manager.get_session() as session:
        # Step A: Migrate Incidents
        incident_id_to_uuid: dict[str, uuid.UUID] = {}

        # Cache existing incidents in PostgreSQL to avoid duplicates
        existing_pg_incidents = {
            inc.incident_id: inc.id
            for inc in session.execute(select(IncidentModel)).scalars().all()
        }
        incident_id_to_uuid.update(existing_pg_incidents)

        for row in incidents_raw:
            inc_id = str(row["incident_id"]).strip()
            if not inc_id or inc_id in incident_id_to_uuid:
                continue

            mitigation = []
            try:
                mitigation = json.loads(row["mitigation_plan"] or "[]")
                if not isinstance(mitigation, list):
                    mitigation = [str(mitigation)]
            except Exception:
                mitigation = []

            threat = {}
            try:
                threat = json.loads(row["threat_intel"] or "{}")
                if not isinstance(threat, dict):
                    threat = {"raw": str(threat)}
            except Exception:
                threat = {}

            risk_val = int(row["risk_score"] or 0)
            risk_val = max(0, min(100, risk_val))

            anom_count = int(row["anomalous_events_count"] or 0)
            anom_count = max(0, anom_count)

            classification = str(row["attack_classification"] or "Unknown").strip() or "Unknown"
            category = str(row["risk_category"] or "Low").strip() or "Low"

            new_uuid = uuid.uuid4()
            model = IncidentModel(
                id=new_uuid,
                incident_id=inc_id,
                idempotency_key=f"legacy:{inc_id}",
                timestamp=parse_iso_datetime(row["timestamp"]),
                attack_classification=classification,
                risk_score=risk_val,
                risk_category=category,
                mitigation_plan=mitigation,
                threat_intel=threat,
                anomalous_events_count=anom_count,
                status="NEW",
            )
            session.add(model)
            incident_id_to_uuid[inc_id] = new_uuid
            stats["migrated_incidents"] += 1

        session.flush()

        # Step B: Migrate Risk History
        for row in risk_raw:
            rel_inc_id = str(row["incident_id"]).strip()
            parent_uuid = incident_id_to_uuid.get(rel_inc_id)
            if not parent_uuid:
                logger.warning(
                    "Skipping orphan risk history row referencing missing incident %s",
                    rel_inc_id,
                )
                continue

            score = int(row["risk_score"] or 0)
            score = max(0, min(100, score))

            risk_model = RiskHistoryModel(
                incident_id=parent_uuid,
                timestamp=parse_iso_datetime(row["timestamp"]),
                risk_score=score,
            )
            session.add(risk_model)
            stats["migrated_risk_history"] += 1

        session.flush()

        # Step C: Migrate IP History
        for row in ip_raw:
            ip = str(row["ip_address"]).strip()
            if not ip:
                continue

            existing_ip = session.execute(
                select(IPHistoryModel).where(IPHistoryModel.ip_address == ip)
            ).scalar_one_or_none()

            off_count = max(0, int(row["offense_count"] or 0))
            score = max(0, min(100, int(row["last_risk_score"] or 0)))
            ts = parse_iso_datetime(row["last_seen"])

            if existing_ip is not None:
                existing_ip.offense_count = max(existing_ip.offense_count, off_count)
                if ts > existing_ip.last_seen:
                    existing_ip.last_seen = ts
                    existing_ip.last_risk_score = score
            else:
                session.add(
                    IPHistoryModel(
                        ip_address=ip,
                        offense_count=off_count,
                        last_seen=ts,
                        last_risk_score=score,
                    )
                )
                stats["migrated_ip_history"] += 1

        session.flush()

        # Step D: Migrate User History
        for row in user_raw:
            username = str(row["username"]).strip()
            if not username:
                continue

            existing_user = session.execute(
                select(UserHistoryModel).where(UserHistoryModel.username == username)
            ).scalar_one_or_none()

            off_count = max(0, int(row["offense_count"] or 0))
            score = max(0, min(100, int(row["last_risk_score"] or 0)))
            ts = parse_iso_datetime(row["last_seen"])

            if existing_user is not None:
                existing_user.offense_count = max(existing_user.offense_count, off_count)
                if ts > existing_user.last_seen:
                    existing_user.last_seen = ts
                    existing_user.last_risk_score = score
            else:
                session.add(
                    UserHistoryModel(
                        username=username,
                        offense_count=off_count,
                        last_seen=ts,
                        last_risk_score=score,
                    )
                )
                stats["migrated_user_history"] += 1

        session.commit()

    # Step E: Post-migration row count verification
    with db_manager.engine.connect() as pg_conn:
        pg_incidents = pg_conn.execute(text("SELECT count(*) FROM incidents")).scalar() or 0
        pg_ip = pg_conn.execute(text("SELECT count(*) FROM ip_history")).scalar() or 0
        pg_user = pg_conn.execute(text("SELECT count(*) FROM user_history")).scalar() or 0
        pg_risk = pg_conn.execute(text("SELECT count(*) FROM risk_history")).scalar() or 0

    stats["pg_total_incidents"] = pg_incidents
    stats["pg_total_ip_history"] = pg_ip
    stats["pg_total_user_history"] = pg_user
    stats["pg_total_risk_history"] = pg_risk

    logger.info("PostgreSQL post-migration verification: %s", stats)

    # Verification assertions
    assert pg_incidents >= stats["sqlite_incidents"], (
        f"Incident verification failed: PG {pg_incidents} < SQLite {stats['sqlite_incidents']}"
    )
    assert pg_risk >= stats["sqlite_risk_history"], (
        f"Risk history verification failed: PG {pg_risk} < SQLite {stats['sqlite_risk_history']}"
    )
    assert pg_ip >= stats["sqlite_ip_history"], (
        f"IP history verification failed: PG {pg_ip} < SQLite {stats['sqlite_ip_history']}"
    )
    assert pg_user >= stats["sqlite_user_history"], (
        f"User history verification failed: PG {pg_user} < SQLite {stats['sqlite_user_history']}"
    )

    return stats


def verify_counts(sqlite_path: Path, db_manager: DatabaseManager) -> dict[str, int]:
    """Compares current row counts between SQLite and PostgreSQL without making changes."""
    if not sqlite_path.exists():
        raise FileNotFoundError(f"Source SQLite database not found at {sqlite_path}")

    with sqlite3.connect(str(sqlite_path)) as sqlite_conn:
        cursor = sqlite_conn.cursor()
        sqlite_incidents = cursor.execute("SELECT count(*) FROM incidents").fetchone()[0]
        sqlite_ip = cursor.execute("SELECT count(*) FROM ip_history").fetchone()[0]
        sqlite_user = cursor.execute("SELECT count(*) FROM user_history").fetchone()[0]
        sqlite_risk = cursor.execute("SELECT count(*) FROM risk_history").fetchone()[0]

    with db_manager.engine.connect() as pg_conn:
        pg_incidents = pg_conn.execute(text("SELECT count(*) FROM incidents")).scalar() or 0
        pg_ip = pg_conn.execute(text("SELECT count(*) FROM ip_history")).scalar() or 0
        pg_user = pg_conn.execute(text("SELECT count(*) FROM user_history")).scalar() or 0
        pg_risk = pg_conn.execute(text("SELECT count(*) FROM risk_history")).scalar() or 0

    stats = {
        "sqlite_incidents": sqlite_incidents,
        "sqlite_ip_history": sqlite_ip,
        "sqlite_user_history": sqlite_user,
        "sqlite_risk_history": sqlite_risk,
        "pg_incidents": pg_incidents,
        "pg_ip_history": pg_ip,
        "pg_user_history": pg_user,
        "pg_risk_history": pg_risk,
    }

    assert pg_incidents >= sqlite_incidents, f"PG incidents ({pg_incidents}) < SQLite ({sqlite_incidents})"
    assert pg_ip >= sqlite_ip, f"PG IP history ({pg_ip}) < SQLite ({sqlite_ip})"
    assert pg_user >= sqlite_user, f"PG user history ({pg_user}) < SQLite ({sqlite_user})"
    assert pg_risk >= sqlite_risk, f"PG risk history ({pg_risk}) < SQLite ({sqlite_risk})"

    return stats


def main() -> None:
    settings = get_settings()
    configure_logging(settings)

    parser = argparse.ArgumentParser(
        description="Migrates historical Zylar SOC state from SQLite to PostgreSQL with count verification."
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=Path("memory/zylar_memory.db"),
        help="Path to source SQLite database file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate extraction and transformation without persisting to PostgreSQL",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip backing up source SQLite database",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Compare record counts between SQLite and PostgreSQL without migrating data",
    )
    args = parser.parse_args()

    db_mgr = DatabaseManager(settings)
    try:
        if args.verify_only:
            stats = verify_counts(sqlite_path=args.sqlite_path, db_manager=db_mgr)
            print("Verification completed successfully:")
            print(json.dumps(stats, indent=2))
            return

        stats = migrate_sqlite_to_postgres(
            sqlite_path=args.sqlite_path,
            db_manager=db_mgr,
            dry_run=args.dry_run,
            backup=not args.no_backup,
        )
        print("Migration completed successfully:")
        print(json.dumps(stats, indent=2))
    except Exception as exc:
        logger.exception("Migration failed: %s", exc)
        sys.exit(1)
    finally:
        db_mgr.dispose()


if __name__ == "__main__":
    main()
