from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from scripts.migrate_sqlite_to_postgres import (
    migrate_sqlite_to_postgres,
    parse_iso_datetime,
)


def test_parse_iso_datetime():
    dt1 = parse_iso_datetime("2026-10-27T10:47:36.337160Z")
    assert dt1.year == 2026
    assert dt1.month == 10
    assert dt1.tzinfo is not None

    dt2 = parse_iso_datetime(None)
    assert dt2.tzinfo is not None


def test_migrate_sqlite_to_postgres_dry_run():
    import sqlite3

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        sqlite_path = Path(tf.name)

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY,
                timestamp TEXT,
                attack_classification TEXT,
                risk_score INTEGER,
                risk_category TEXT,
                mitigation_plan TEXT,
                threat_intel TEXT,
                anomalous_events_count INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE ip_history (
                ip_address TEXT PRIMARY KEY,
                offense_count INTEGER DEFAULT 0,
                last_seen TEXT,
                last_risk_score INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE user_history (
                username TEXT PRIMARY KEY,
                offense_count INTEGER DEFAULT 0,
                last_seen TEXT,
                last_risk_score INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                incident_id TEXT,
                risk_score INTEGER
            )
            """
        )
        cur.execute(
            """
            INSERT INTO incidents VALUES (
                'ZYLAR-INC-UNIT-1', '2026-10-27T12:00:00Z', 'Brute Force', 75, 'High',
                '["Block IP"]', '{"ttp": "T1110"}', 3
            )
            """
        )
        conn.commit()
        conn.close()

        mock_mgr = MagicMock()
        stats = migrate_sqlite_to_postgres(
            sqlite_path=sqlite_path,
            db_manager=mock_mgr,
            dry_run=True,
            backup=False,
        )

        assert stats["sqlite_incidents"] == 1
        assert stats["migrated_incidents"] == 0
        mock_mgr.get_session.assert_not_called()
    finally:
        if sqlite_path.exists():
            sqlite_path.unlink()
