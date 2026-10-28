from __future__ import annotations

import argparse
import json
import logging
import shutil
import sqlite3
import sys
import uuid
from datetime import UTC, datetime, timedelta
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


class MigrationTimestampError(ValueError):
    """Raised when a historical timestamp is missing or malformed."""


class MigrationVerificationError(RuntimeError):
    """Raised when source SQLite records do not correspond to target PostgreSQL records."""


def parse_iso_datetime(value: str | None, context: str = "") -> datetime:
    """Parses ISO timestamp strings into timezone-aware UTC datetime.

    Raises MigrationTimestampError on missing or invalid timestamps to prevent silent alteration
    of historical records.
    """
    if not value or not str(value).strip():
        raise MigrationTimestampError(
            f"Missing required timestamp in historical record: {context or 'unknown'}"
        )
    clean_val = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(clean_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception as exc:
        raise MigrationTimestampError(
            f"Invalid ISO timestamp '{value}' in historical record ({context or 'unknown'}): {exc}"
        ) from exc


def backup_sqlite_database(sqlite_path: Path) -> Path:
    """Creates a timestamped backup of the source SQLite database."""
    backup_path = sqlite_path.with_suffix(f".db.bak_{int(datetime.now(UTC).timestamp())}")
    shutil.copy2(sqlite_path, backup_path)
    # Also maintain a standard .db.bak copy
    standard_bak = sqlite_path.with_suffix(".db.bak")
    shutil.copy2(sqlite_path, standard_bak)
    logger.info("Backed up SQLite database to %s and %s", backup_path, standard_bak)
    return standard_bak


def verify_record_level_correspondence(
    sqlite_path: Path,
    db_manager: DatabaseManager,
    allow_orphans: bool = False,
    mode: str = "merge",
) -> dict[str, Any]:
    """Verifies complete record-level correspondence from SQLite to PostgreSQL.

    Separates exact preservation from intentional transformations and reconciles target-only records.
    Supports two explicit operational modes:
      - 'clean': Strict 1-to-1 import verification. Target database must not contain pre-existing
        or target-only records, and historical offender counts must match source exactly.
      - 'merge': Migration into a live/populated database. Source contribution preservation is verified,
        subsequent offender updates are verified under monotonic non-regression, and target-only
        records are reconciled into a distinct inventory.

    Manifest categories:
      - exact_match: Source records preserved with bitwise/schema equality in PostgreSQL.
      - approved_transformation: Source records intentionally converted under approved schema policies
        (e.g., score clamping to [0, 100], JSON default substitution, wrapping non-lists).
      - missing: Source records missing in PostgreSQL.
      - duplicate: Multiple source records claiming the same target record.
      - rejected: Unapproved discrepancies or regressions.
      - orphaned: Source records referencing non-existent parent entities.
      - target_only: Authoritative PostgreSQL records that did not originate from SQLite.
    """
    if not sqlite_path.exists():
        raise FileNotFoundError(f"Source SQLite database not found at {sqlite_path}")

    if mode not in ("clean", "merge"):
        raise ValueError(f"Invalid verification mode '{mode}'. Must be 'clean' or 'merge'.")

    sqlite_conn = sqlite3.connect(str(sqlite_path))
    try:
        sqlite_conn.row_factory = sqlite3.Row
        cur = sqlite_conn.cursor()
        incidents_raw = cur.execute("SELECT * FROM incidents").fetchall()
        ip_raw = cur.execute("SELECT * FROM ip_history").fetchall()
        user_raw = cur.execute("SELECT * FROM user_history").fetchall()
        risk_raw = cur.execute("SELECT * FROM risk_history").fetchall()
    finally:
        sqlite_conn.close()

    counts: dict[str, int] = {
        "exact_match": 0,
        "approved_transformation": 0,
        "matched": 0,
        "missing": 0,
        "duplicate": 0,
        "rejected": 0,
        "orphaned": 0,
        "target_only": 0,
    }

    breakdown: dict[str, dict[str, Any]] = {
        "incidents": {
            "source_count": len(incidents_raw),
            "target_count": 0,
            "exact_match": 0,
            "approved_transformation": 0,
            "matched": 0,
            "missing": 0,
            "rejected": 0,
            "target_only": 0,
        },
        "risk_history": {
            "source_count": len(risk_raw),
            "target_count": 0,
            "exact_match": 0,
            "approved_transformation": 0,
            "matched": 0,
            "missing": 0,
            "duplicate": 0,
            "orphaned": 0,
            "target_only": 0,
        },
        "ip_history": {
            "source_count": len(ip_raw),
            "target_count": 0,
            "exact_match": 0,
            "approved_transformation": 0,
            "matched": 0,
            "missing": 0,
            "rejected": 0,
            "target_only": 0,
        },
        "user_history": {
            "source_count": len(user_raw),
            "target_count": 0,
            "exact_match": 0,
            "approved_transformation": 0,
            "matched": 0,
            "missing": 0,
            "rejected": 0,
            "target_only": 0,
        },
    }

    transformed_details: list[dict[str, Any]] = []
    orphaned_risk_records: list[dict[str, Any]] = []
    matched_incident_ids: list[str] = []
    matched_risk_pairs: list[dict[str, Any]] = []
    matched_pg_risk_ids: set[int] = set()

    with db_manager.get_session() as session:
        # 1. Incident Correspondence
        for row in incidents_raw:
            inc_id = str(row["incident_id"]).strip()
            pg_inc = session.execute(
                select(IncidentModel).where(IncidentModel.incident_id == inc_id)
            ).scalar_one_or_none()

            if pg_inc is None:
                counts["missing"] += 1
                breakdown["incidents"]["missing"] += 1
                raise MigrationVerificationError(
                    f"Incident verification failed: '{inc_id}' exists in SQLite but missing in PostgreSQL"
                )

            is_transformed = False
            reasons: list[dict[str, Any]] = []

            # Check status
            row_keys = row.keys() if hasattr(row, "keys") else []
            expected_status = (row["status"] or "NEW") if "status" in row_keys else "NEW"
            if pg_inc.status != expected_status:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' status mismatch: PG '{pg_inc.status}' != SQLite '{expected_status}'"
                )

            # Check core attributes
            expected_class = str(row["attack_classification"] or "Unknown").strip() or "Unknown"
            if pg_inc.attack_classification != expected_class:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' attack_classification mismatch: PG '{pg_inc.attack_classification}' != SQLite '{expected_class}'"
                )

            raw_score = int(row["risk_score"] or 0)
            if not (0 <= raw_score <= 100):
                is_transformed = True
                expected_score = max(0, min(100, raw_score))
                reasons.append({
                    "field": "risk_score",
                    "source_value": raw_score,
                    "target_value": expected_score,
                    "reason": "clamped to range [0, 100]",
                    "policy": "SCHEMA_RANGE_ENFORCEMENT",
                })
            else:
                expected_score = raw_score

            if pg_inc.risk_score != expected_score:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' risk_score mismatch: PG {pg_inc.risk_score} != SQLite {expected_score}"
                )

            expected_cat = str(row["risk_category"] or "Low").strip() or "Low"
            if pg_inc.risk_category != expected_cat:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' risk_category mismatch: PG '{pg_inc.risk_category}' != SQLite '{expected_cat}'"
                )

            raw_anom = int(row["anomalous_events_count"] or 0)
            if raw_anom < 0:
                is_transformed = True
                expected_anom = 0
                reasons.append({
                    "field": "anomalous_events_count",
                    "source_value": raw_anom,
                    "target_value": 0,
                    "reason": "clamped from negative to 0",
                    "policy": "SCHEMA_RANGE_ENFORCEMENT",
                })
            else:
                expected_anom = raw_anom

            if pg_inc.anomalous_events_count != expected_anom:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' anomalous_events_count mismatch: PG {pg_inc.anomalous_events_count} != SQLite {expected_anom}"
                )

            # Check parsed JSON mitigation plan
            raw_mitigation = row["mitigation_plan"]
            try:
                parsed_mitigation = json.loads(raw_mitigation or "[]")
                if not isinstance(parsed_mitigation, list):
                    parsed_mitigation = [str(parsed_mitigation)]
                    is_transformed = True
                    reasons.append({
                        "field": "mitigation_plan",
                        "source_value": raw_mitigation,
                        "target_value": parsed_mitigation,
                        "reason": "non-list wrapped in list",
                        "policy": "SCHEMA_COMPATIBILITY",
                    })
            except Exception:
                parsed_mitigation = []
                is_transformed = True
                reasons.append({
                    "field": "mitigation_plan",
                    "source_value": raw_mitigation,
                    "target_value": [],
                    "reason": "malformed JSON substituted with default",
                    "policy": "SCHEMA_FALLBACK",
                })

            if pg_inc.mitigation_plan != parsed_mitigation:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' mitigation_plan mismatch: PG {pg_inc.mitigation_plan} != SQLite {parsed_mitigation}"
                )

            # Check parsed JSON threat intel
            raw_threat = row["threat_intel"]
            try:
                parsed_threat = json.loads(raw_threat or "{}")
                if not isinstance(parsed_threat, dict):
                    parsed_threat = {"raw": str(parsed_threat)}
                    is_transformed = True
                    reasons.append({
                        "field": "threat_intel",
                        "source_value": raw_threat,
                        "target_value": parsed_threat,
                        "reason": "non-dict wrapped in dict",
                        "policy": "SCHEMA_COMPATIBILITY",
                    })
            except Exception:
                parsed_threat = {}
                is_transformed = True
                reasons.append({
                    "field": "threat_intel",
                    "source_value": raw_threat,
                    "target_value": {},
                    "reason": "malformed JSON substituted with default",
                    "policy": "SCHEMA_FALLBACK",
                })

            if pg_inc.threat_intel != parsed_threat:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' threat_intel mismatch: PG {pg_inc.threat_intel} != SQLite {parsed_threat}"
                )

            sqlite_ts = parse_iso_datetime(row["timestamp"], context=f"SQLite incident {inc_id}")
            if abs((pg_inc.timestamp - sqlite_ts).total_seconds()) > 2.0:
                counts["rejected"] += 1
                raise MigrationVerificationError(
                    f"Incident '{inc_id}' timestamp divergence: PG {pg_inc.timestamp} vs SQLite {sqlite_ts}"
                )

            if is_transformed:
                counts["approved_transformation"] += 1
                breakdown["incidents"]["approved_transformation"] += 1
                transformed_details.append({
                    "entity": "incident",
                    "id": inc_id,
                    "transformations": reasons,
                    "approval_policy": "SCHEMA_COMPATIBILITY_TRANSFORMATION",
                })
            else:
                counts["exact_match"] += 1
                breakdown["incidents"]["exact_match"] += 1

            counts["matched"] += 1
            breakdown["incidents"]["matched"] += 1
            matched_incident_ids.append(inc_id)

        # 2. Risk History Correspondence (Strict 1-to-1 matching)
        for row in risk_raw:
            rel_inc_id = str(row["incident_id"]).strip()
            parent_inc = session.execute(
                select(IncidentModel).where(IncidentModel.incident_id == rel_inc_id)
            ).scalar_one_or_none()

            if parent_inc is None:
                orphaned_risk_records.append(
                    {
                        "source_risk_id": row["id"],
                        "incident_id": rel_inc_id,
                        "risk_score": row["risk_score"],
                        "timestamp": row["timestamp"],
                    }
                )
                counts["orphaned"] += 1
                breakdown["risk_history"]["orphaned"] += 1
                continue

            raw_score = int(row["risk_score"] or 0)
            is_transformed = not (0 <= raw_score <= 100)
            expected_score = max(0, min(100, raw_score))
            sqlite_ts = parse_iso_datetime(
                row["timestamp"], context=f"SQLite risk row {row['id']} ({rel_inc_id})"
            )

            matching_pg_risk = session.execute(
                select(RiskHistoryModel).where(
                    RiskHistoryModel.incident_id == parent_inc.id,
                    RiskHistoryModel.risk_score == expected_score,
                )
            ).scalars().all()

            # Find distinct, unclaimed PostgreSQL row
            chosen_cand: RiskHistoryModel | None = None
            for cand in matching_pg_risk:
                if cand.id in matched_pg_risk_ids:
                    continue
                if abs((cand.timestamp - sqlite_ts).total_seconds()) <= 2.0:
                    chosen_cand = cand
                    break

            if chosen_cand is None:
                all_ts_matches = [
                    cand
                    for cand in matching_pg_risk
                    if abs((cand.timestamp - sqlite_ts).total_seconds()) <= 2.0
                ]
                if all_ts_matches:
                    counts["duplicate"] += 1
                    breakdown["risk_history"]["duplicate"] += 1
                    raise MigrationVerificationError(
                        f"Risk history duplicate match detected: SQLite risk row {row['id']} "
                        f"for incident '{rel_inc_id}' cannot be matched to a distinct PostgreSQL row. "
                        f"All matching target rows are already claimed by other source rows."
                    )
                else:
                    counts["missing"] += 1
                    breakdown["risk_history"]["missing"] += 1
                    raise MigrationVerificationError(
                        f"Risk history row {row['id']} for incident '{rel_inc_id}' with score {expected_score} "
                        f"and timestamp {sqlite_ts} is missing in PostgreSQL."
                    )

            matched_pg_risk_ids.add(chosen_cand.id)
            matched_risk_pairs.append({
                "source_risk_id": row["id"],
                "target_risk_id": chosen_cand.id,
                "incident_id": rel_inc_id,
            })

            if is_transformed:
                counts["approved_transformation"] += 1
                breakdown["risk_history"]["approved_transformation"] += 1
                transformed_details.append({
                    "entity": "risk_history",
                    "id": row["id"],
                    "transformations": [{
                        "field": "risk_score",
                        "source_value": raw_score,
                        "target_value": expected_score,
                        "reason": "clamped to [0, 100]",
                        "policy": "SCHEMA_RANGE_ENFORCEMENT",
                    }],
                })
            else:
                counts["exact_match"] += 1
                breakdown["risk_history"]["exact_match"] += 1

            counts["matched"] += 1
            breakdown["risk_history"]["matched"] += 1

        # Strict check on orphaned records
        if orphaned_risk_records and not allow_orphans:
            counts["rejected"] += len(orphaned_risk_records)
            raise MigrationVerificationError(
                f"Migration verification failed: found {len(orphaned_risk_records)} orphaned risk records in SQLite "
                f"referencing missing incidents: {[r['incident_id'] for r in orphaned_risk_records[:5]]}"
            )

        # 3. IP History Correspondence
        for row in ip_raw:
            ip = str(row["ip_address"]).strip()
            if not ip:
                continue

            pg_ip = session.execute(
                select(IPHistoryModel).where(IPHistoryModel.ip_address == ip)
            ).scalar_one_or_none()

            if pg_ip is None:
                counts["missing"] += 1
                breakdown["ip_history"]["missing"] += 1
                raise MigrationVerificationError(
                    f"IP history for '{ip}' exists in SQLite but missing in PostgreSQL"
                )

            raw_offense = int(row["offense_count"] or 0)
            raw_score = int(row["last_risk_score"] or 0)
            is_transformed = raw_offense < 0 or not (0 <= raw_score <= 100)
            sqlite_count = max(0, raw_offense)
            expected_score = max(0, min(100, raw_score))
            sqlite_ts = parse_iso_datetime(row["last_seen"], context=f"SQLite IP {ip}")

            if mode == "clean":
                if pg_ip.offense_count != sqlite_count:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' offense count mismatch in clean import: PG {pg_ip.offense_count} != SQLite {sqlite_count}"
                    )
                if pg_ip.last_risk_score != expected_score:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' last_risk_score mismatch in clean import: PG {pg_ip.last_risk_score} != SQLite {expected_score}"
                    )
                if abs((pg_ip.last_seen - sqlite_ts).total_seconds()) > 2.0:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' last_seen timestamp divergence in clean import: PG {pg_ip.last_seen} vs SQLite {sqlite_ts}"
                    )
            else:  # merge mode
                if pg_ip.offense_count < sqlite_count:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' offense count regressed: PG {pg_ip.offense_count} < SQLite {sqlite_count}"
                    )
                if pg_ip.last_seen < (sqlite_ts - timedelta(seconds=2)):
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' last_seen timestamp regressed: PG {pg_ip.last_seen} < SQLite {sqlite_ts}"
                    )
                if pg_ip.last_risk_score is None:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' has null last_risk_score in PostgreSQL"
                    )
                if pg_ip.offense_count == sqlite_count and pg_ip.last_risk_score != expected_score:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"IP history for '{ip}' last_risk_score mismatch: PG {pg_ip.last_risk_score} != SQLite {expected_score}"
                    )

            if is_transformed:
                counts["approved_transformation"] += 1
                breakdown["ip_history"]["approved_transformation"] += 1
                transformed_details.append({
                    "entity": "ip_history",
                    "id": ip,
                    "transformations": [{
                        "field": "offense_count_or_risk_score",
                        "source_value": f"count={raw_offense}, score={raw_score}",
                        "target_value": f"count={sqlite_count}, score={expected_score}",
                        "reason": "clamped negative count or out-of-range score",
                        "policy": "SCHEMA_RANGE_ENFORCEMENT",
                    }],
                })
            else:
                counts["exact_match"] += 1
                breakdown["ip_history"]["exact_match"] += 1

            counts["matched"] += 1
            breakdown["ip_history"]["matched"] += 1

        # 4. User History Correspondence
        for row in user_raw:
            username = str(row["username"]).strip()
            if not username:
                continue

            pg_user = session.execute(
                select(UserHistoryModel).where(UserHistoryModel.username == username)
            ).scalar_one_or_none()

            if pg_user is None:
                counts["missing"] += 1
                breakdown["user_history"]["missing"] += 1
                raise MigrationVerificationError(
                    f"User history for '{username}' exists in SQLite but missing in PostgreSQL"
                )

            raw_offense = int(row["offense_count"] or 0)
            raw_score = int(row["last_risk_score"] or 0)
            is_transformed = raw_offense < 0 or not (0 <= raw_score <= 100)
            sqlite_count = max(0, raw_offense)
            expected_score = max(0, min(100, raw_score))
            sqlite_ts = parse_iso_datetime(row["last_seen"], context=f"SQLite user {username}")

            if mode == "clean":
                if pg_user.offense_count != sqlite_count:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' offense count mismatch in clean import: PG {pg_user.offense_count} != SQLite {sqlite_count}"
                    )
                if pg_user.last_risk_score != expected_score:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' last_risk_score mismatch in clean import: PG {pg_user.last_risk_score} != SQLite {expected_score}"
                    )
                if abs((pg_user.last_seen - sqlite_ts).total_seconds()) > 2.0:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' last_seen timestamp divergence in clean import: PG {pg_user.last_seen} vs SQLite {sqlite_ts}"
                    )
            else:  # merge mode
                if pg_user.offense_count < sqlite_count:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' offense count regressed: PG {pg_user.offense_count} < SQLite {sqlite_count}"
                    )
                if pg_user.last_seen < (sqlite_ts - timedelta(seconds=2)):
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' last_seen timestamp regressed: PG {pg_user.last_seen} < SQLite {sqlite_ts}"
                    )
                if pg_user.last_risk_score is None:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' has null last_risk_score in PostgreSQL"
                    )
                if pg_user.offense_count == sqlite_count and pg_user.last_risk_score != expected_score:
                    counts["rejected"] += 1
                    raise MigrationVerificationError(
                        f"User history for '{username}' last_risk_score mismatch: PG {pg_user.last_risk_score} != SQLite {expected_score}"
                    )

            if is_transformed:
                counts["approved_transformation"] += 1
                breakdown["user_history"]["approved_transformation"] += 1
                transformed_details.append({
                    "entity": "user_history",
                    "id": username,
                    "transformations": [{
                        "field": "offense_count_or_risk_score",
                        "source_value": f"count={raw_offense}, score={raw_score}",
                        "target_value": f"count={sqlite_count}, score={expected_score}",
                        "reason": "clamped negative count or out-of-range score",
                        "policy": "SCHEMA_RANGE_ENFORCEMENT",
                    }],
                })
            else:
                counts["exact_match"] += 1
                breakdown["user_history"]["exact_match"] += 1

            counts["matched"] += 1
            breakdown["user_history"]["matched"] += 1

    # Bidirectional Reconciliation: Target-Only Inventory
    with db_manager.engine.connect() as pg_conn:
        all_pg_inc_ids = set(pg_conn.execute(text("SELECT incident_id FROM incidents")).scalars().all())
        all_pg_ips = set(pg_conn.execute(text("SELECT ip_address FROM ip_history")).scalars().all())
        all_pg_users = set(pg_conn.execute(text("SELECT username FROM user_history")).scalars().all())
        total_pg_risk = pg_conn.execute(text("SELECT count(*) FROM risk_history")).scalar() or 0

    sqlite_inc_ids = {str(row["incident_id"]).strip() for row in incidents_raw}
    sqlite_ips = {str(row["ip_address"]).strip() for row in ip_raw if str(row["ip_address"]).strip()}
    sqlite_users = {str(row["username"]).strip() for row in user_raw if str(row["username"]).strip()}

    target_only_incidents = sorted(all_pg_inc_ids - sqlite_inc_ids)
    target_only_ips = sorted(all_pg_ips - sqlite_ips)
    target_only_users = sorted(all_pg_users - sqlite_users)
    target_only_risk_count = max(0, total_pg_risk - len(matched_pg_risk_ids))

    target_only_total = (
        len(target_only_incidents)
        + len(target_only_ips)
        + len(target_only_users)
        + target_only_risk_count
    )
    counts["target_only"] = target_only_total
    breakdown["incidents"]["target_only"] = len(target_only_incidents)
    breakdown["risk_history"]["target_only"] = target_only_risk_count
    breakdown["ip_history"]["target_only"] = len(target_only_ips)
    breakdown["user_history"]["target_only"] = len(target_only_users)

    breakdown["incidents"]["target_count"] = len(all_pg_inc_ids)
    breakdown["risk_history"]["target_count"] = total_pg_risk
    breakdown["ip_history"]["target_count"] = len(all_pg_ips)
    breakdown["user_history"]["target_count"] = len(all_pg_users)

    if mode == "clean" and target_only_total > 0:
        counts["rejected"] += target_only_total
        raise MigrationVerificationError(
            f"Clean import verification failed: target database contains {target_only_total} target-only records "
            f"({len(target_only_incidents)} incidents, {len(target_only_ips)} IPs, {len(target_only_users)} users, "
            f"{target_only_risk_count} risk records). Clean import mode requires target counts to strictly equal source counts."
        )

    manifest = {
        "status": "VERIFIED",
        "mode": mode,
        "counts": counts,
        "breakdown": breakdown,
        "target_only": {
            "total_count": target_only_total,
            "incidents_count": len(target_only_incidents),
            "risk_history_count": target_only_risk_count,
            "ip_history_count": len(target_only_ips),
            "user_history_count": len(target_only_users),
            "sample_target_only_incident_ids": target_only_incidents[:10],
            "target_only_ips": target_only_ips,
            "target_only_users": target_only_users,
        },
        "matched_incident_ids": matched_incident_ids,
        "matched_risk_pairs_count": len(matched_risk_pairs),
        "transformed_details": transformed_details,
        "orphaned_details": orphaned_risk_records,
    }

    logger.info("Record-level correspondence verified successfully (%s mode): %s", mode, manifest)
    return manifest


def migrate_sqlite_to_postgres(
    sqlite_path: Path,
    db_manager: DatabaseManager,
    dry_run: bool = False,
    backup: bool = True,
    allow_orphans: bool = False,
    mode: str = "merge",
) -> dict[str, Any]:
    """Migrates historical SOC state from SQLite to PostgreSQL with record-level verification."""
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

    stats: dict[str, Any] = {
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
                timestamp=parse_iso_datetime(row["timestamp"], context=f"incident {inc_id}"),
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
                timestamp=parse_iso_datetime(
                    row["timestamp"], context=f"risk {row['id']} ({rel_inc_id})"
                ),
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
            ts = parse_iso_datetime(row["last_seen"], context=f"ip {ip}")

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
            ts = parse_iso_datetime(row["last_seen"], context=f"user {username}")

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

    # Step E: Post-migration record-level correspondence verification
    verification_manifest = verify_record_level_correspondence(
        sqlite_path, db_manager, allow_orphans=allow_orphans, mode=mode
    )
    stats["verification_manifest"] = verification_manifest
    return stats


def main() -> None:
    settings = get_settings()
    configure_logging(settings)

    parser = argparse.ArgumentParser(
        description="Migrates historical Zylar SOC state from SQLite to PostgreSQL with record correspondence verification."
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=(
            Path("backups/legacy_sqlite/zylar_memory.db")
            if Path("backups/legacy_sqlite/zylar_memory.db").exists()
            else Path("memory/zylar_memory.db")
        ),
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
        help="Verify record-level correspondence between SQLite and PostgreSQL without migrating data",
    )
    parser.add_argument(
        "--allow-orphans",
        action="store_true",
        help="Allow orphaned records during verification if explicitly documented and approved",
    )
    parser.add_argument(
        "--mode",
        choices=["clean", "merge"],
        default="merge",
        help="Verification mode: clean (strict target equality, zero target-only records) or merge (live populated database with target-only reconciliation)",
    )
    args = parser.parse_args()

    db_mgr = DatabaseManager(settings)
    try:
        if args.verify_only:
            manifest = verify_record_level_correspondence(
                sqlite_path=args.sqlite_path,
                db_manager=db_mgr,
                allow_orphans=args.allow_orphans,
                mode=args.mode,
            )
            print("Record-level verification completed successfully:")
            print(json.dumps(manifest, indent=2))
            return

        stats = migrate_sqlite_to_postgres(
            sqlite_path=args.sqlite_path,
            db_manager=db_mgr,
            dry_run=args.dry_run,
            backup=not args.no_backup,
            allow_orphans=args.allow_orphans,
            mode=args.mode,
        )
        print("Migration and verification completed successfully:")
        print(json.dumps(stats, indent=2))
    except Exception as exc:
        logger.exception("Migration/Verification failed: %s", exc)
        sys.exit(1)
    finally:
        db_mgr.dispose()


if __name__ == "__main__":
    main()
