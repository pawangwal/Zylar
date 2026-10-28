from __future__ import annotations

import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from scripts.migrate_sqlite_to_postgres import (
    MigrationTimestampError,
    MigrationVerificationError,
    migrate_sqlite_to_postgres,
    parse_iso_datetime,
    verify_record_level_correspondence,
)

from zylar.persistence.models import (
    IncidentModel,
    IPHistoryModel,
    RiskHistoryModel,
    UserHistoryModel,
)


def test_parse_iso_datetime():
    dt1 = parse_iso_datetime("2026-10-27T10:47:36.337160Z")
    assert dt1.year == 2026
    assert dt1.month == 10
    assert dt1.tzinfo is not None

    dt2 = parse_iso_datetime("2026-10-27T10:47:36.337160+00:00")
    assert dt2.year == 2026
    assert dt2.tzinfo is not None

    # Strict timestamp enforcement: None, empty, or unparseable raises MigrationTimestampError
    with pytest.raises(MigrationTimestampError, match="Missing required timestamp"):
        parse_iso_datetime(None, context="test incident")

    with pytest.raises(MigrationTimestampError, match="Missing required timestamp"):
        parse_iso_datetime("   ", context="test incident")

    with pytest.raises(MigrationTimestampError, match="Invalid ISO timestamp"):
        parse_iso_datetime("not-a-timestamp", context="test incident")


def _safe_unlink(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def test_verify_record_level_correspondence_detects_mismatch():
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

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
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        cur.execute(
            """
            INSERT INTO incidents VALUES (
                'ZYLAR-INC-FAIL-1', '2026-10-27T12:00:00Z', 'Brute Force', 75, 'High',
                '["Block IP"]', '{"ttp": "T1110"}', 3
            )
            """
        )
        conn.commit()
        conn.close()

        # Mock db manager where the incident does NOT exist in PG
        mock_mgr = MagicMock()
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        with pytest.raises(MigrationVerificationError, match="exists in SQLite but missing in PostgreSQL"):
            verify_record_level_correspondence(sqlite_path, mock_mgr)
    finally:
        _safe_unlink(sqlite_path)


def test_verify_record_level_correspondence_success():
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

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
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        cur.execute(
            """
            INSERT INTO incidents VALUES (
                'ZYLAR-INC-OK-1', '2026-10-27T12:00:00Z', 'Brute Force', 75, 'High',
                '["Block IP"]', '{"ttp": "T1110"}', 3
            )
            """
        )
        cur.execute("INSERT INTO ip_history VALUES ('192.168.1.10', 5, '2026-10-27T12:00:00Z', 75)")
        cur.execute("INSERT INTO user_history VALUES ('alice', 4, '2026-10-27T12:00:00Z', 75)")
        cur.execute("INSERT INTO risk_history VALUES (1, '2026-10-27T12:00:00Z', 'ZYLAR-INC-OK-1', 75)")
        conn.commit()
        conn.close()

        # Mock matching PG models
        inc_uuid = uuid.uuid4()
        pg_inc = IncidentModel(
            id=inc_uuid,
            incident_id="ZYLAR-INC-OK-1",
            idempotency_key="legacy:ZYLAR-INC-OK-1",
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            attack_classification="Brute Force",
            risk_score=75,
            risk_category="High",
            mitigation_plan=["Block IP"],
            threat_intel={"ttp": "T1110"},
            anomalous_events_count=3,
            status="NEW",
        )
        pg_ip = IPHistoryModel(
            ip_address="192.168.1.10",
            offense_count=5,
            last_seen=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            last_risk_score=75,
        )
        pg_user = UserHistoryModel(
            username="alice",
            offense_count=4,
            last_seen=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            last_risk_score=75,
        )
        pg_risk = RiskHistoryModel(
            id=101,
            incident_id=inc_uuid,
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            risk_score=75,
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()

        def mock_execute(query):
            mock_res = MagicMock()
            q_str = str(query)
            if "incidents" in q_str:
                mock_res.scalar_one_or_none.return_value = pg_inc
            elif "ip_history" in q_str:
                mock_res.scalar_one_or_none.return_value = pg_ip
            elif "user_history" in q_str:
                mock_res.scalar_one_or_none.return_value = pg_user
            elif "risk_history" in q_str:
                mock_res.scalars.return_value.all.return_value = [pg_risk]
            return mock_res

        def mock_conn_execute(q):
            m = MagicMock()
            q_str = str(q)
            if "incidents" in q_str:
                m.scalars.return_value.all.return_value = ["ZYLAR-INC-OK-1"]
            elif "ip_history" in q_str:
                m.scalars.return_value.all.return_value = ["192.168.1.10"]
            elif "user_history" in q_str:
                m.scalars.return_value.all.return_value = ["alice"]
            elif "risk_history" in q_str:
                m.scalar.return_value = 1
            else:
                m.scalars.return_value.all.return_value = []
                m.scalar.return_value = 0
            return m

        mock_session.execute.side_effect = mock_execute
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session
        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.side_effect = mock_conn_execute

        manifest = verify_record_level_correspondence(sqlite_path, mock_mgr, mode="clean")
        assert manifest["status"] == "VERIFIED"
        assert manifest["counts"]["matched"] == 4
        assert manifest["counts"]["exact_match"] == 4
        assert manifest["counts"]["approved_transformation"] == 0
        assert manifest["counts"]["target_only"] == 0
        assert manifest["counts"]["duplicate"] == 0
        assert manifest["breakdown"]["incidents"]["exact_match"] == 1
        assert manifest["breakdown"]["risk_history"]["exact_match"] == 1
        assert manifest["breakdown"]["ip_history"]["exact_match"] == 1
        assert manifest["breakdown"]["user_history"]["exact_match"] == 1
        assert manifest["matched_risk_pairs_count"] == 1
    finally:
        _safe_unlink(sqlite_path)


def test_migrate_sqlite_to_postgres_dry_run():
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

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
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
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
        _safe_unlink(sqlite_path)


def test_verify_record_level_correspondence_rejects_duplicate_risk_matching():
    """Confirms that one PG risk row cannot satisfy multiple SQLite risk rows."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT,
                risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT,
                threat_intel TEXT, anomalous_events_count INTEGER
            )
            """
        )
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        cur.execute(
            "INSERT INTO incidents VALUES ('ZYLAR-INC-DUP-1', '2026-10-27T12:00:00Z', 'Brute Force', 75, 'High', '[]', '{}', 1)"
        )
        # Two distinct SQLite risk rows with identical parent, score, and timestamp
        cur.execute("INSERT INTO risk_history VALUES (1, '2026-10-27T12:00:00Z', 'ZYLAR-INC-DUP-1', 75)")
        cur.execute("INSERT INTO risk_history VALUES (2, '2026-10-27T12:00:00Z', 'ZYLAR-INC-DUP-1', 75)")
        conn.commit()
        conn.close()

        inc_uuid = uuid.uuid4()
        pg_inc = IncidentModel(
            id=inc_uuid,
            incident_id="ZYLAR-INC-DUP-1",
            idempotency_key="legacy:ZYLAR-INC-DUP-1",
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            attack_classification="Brute Force",
            risk_score=75,
            risk_category="High",
            mitigation_plan=[],
            threat_intel={},
            anomalous_events_count=1,
            status="NEW",
        )
        # PostgreSQL ONLY has ONE matching risk row
        pg_risk_single = RiskHistoryModel(
            id=999,
            incident_id=inc_uuid,
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            risk_score=75,
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()

        def mock_execute(query):
            mock_res = MagicMock()
            q_str = str(query)
            if "incidents" in q_str:
                mock_res.scalar_one_or_none.return_value = pg_inc
            elif "risk_history" in q_str:
                # Returns only the single PG risk row
                mock_res.scalars.return_value.all.return_value = [pg_risk_single]
            elif "ip_history" in q_str:
                mock_res.scalar_one_or_none.return_value = None
            elif "user_history" in q_str:
                mock_res.scalar_one_or_none.return_value = None
            return mock_res

        mock_session.execute.side_effect = mock_execute
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        with pytest.raises(MigrationVerificationError, match="duplicate match detected"):
            verify_record_level_correspondence(sqlite_path, mock_mgr)
    finally:
        _safe_unlink(sqlite_path)


def test_verify_record_level_correspondence_rejects_unapproved_orphaned_records():
    """Confirms that orphaned risk records fail verification unless allow_orphans=True."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT,
                risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT,
                threat_intel TEXT, anomalous_events_count INTEGER
            )
            """
        )
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        # Orphaned risk row referencing non-existent incident
        cur.execute("INSERT INTO risk_history VALUES (99, '2026-10-27T12:00:00Z', 'ZYLAR-INC-NONEXISTENT', 80)")
        conn.commit()
        conn.close()

        mock_mgr = MagicMock()
        mock_session = MagicMock()
        # Incident is missing in PG
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session
        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.return_value.scalar.return_value = 0

        # By default, orphaned records fail verification
        with pytest.raises(MigrationVerificationError, match="orphaned risk records in SQLite"):
            verify_record_level_correspondence(sqlite_path, mock_mgr, allow_orphans=False)

        # With allow_orphans=True, verification completes and reports the orphan
        manifest = verify_record_level_correspondence(sqlite_path, mock_mgr, allow_orphans=True)
        assert manifest["counts"]["orphaned"] == 1
        assert len(manifest["orphaned_details"]) == 1
        assert manifest["orphaned_details"][0]["incident_id"] == "ZYLAR-INC-NONEXISTENT"
    finally:
        _safe_unlink(sqlite_path)


def test_verify_record_level_correspondence_tracks_transformed_records():
    """Confirms that clamped values or substituted JSON fallbacks are recorded as transformations."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT,
                risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT,
                threat_intel TEXT, anomalous_events_count INTEGER
            )
            """
        )
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        # Out-of-bounds score (150) and invalid JSON mitigation plan
        cur.execute(
            """
            INSERT INTO incidents VALUES (
                'ZYLAR-INC-TRANSFORM-1', '2026-10-27T12:00:00Z', 'DDoS', 150, 'Critical',
                'invalid-json-string', '{"ttp": "T1498"}', -5
            )
            """
        )
        conn.commit()
        conn.close()

        # PG model has the clamped score (100), clamped anomalous events (0), and fallback plan ([])
        inc_uuid = uuid.uuid4()
        pg_inc = IncidentModel(
            id=inc_uuid,
            incident_id="ZYLAR-INC-TRANSFORM-1",
            idempotency_key="legacy:ZYLAR-INC-TRANSFORM-1",
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            attack_classification="DDoS",
            risk_score=100,
            risk_category="Critical",
            mitigation_plan=[],
            threat_intel={"ttp": "T1498"},
            anomalous_events_count=0,
            status="NEW",
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = pg_inc
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        def mock_conn_execute(q):
            m = MagicMock()
            q_str = str(q)
            if "incidents" in q_str:
                m.scalars.return_value.all.return_value = ["ZYLAR-INC-TRANSFORM-1"]
            elif "risk_history" in q_str:
                m.scalar.return_value = 0
            else:
                m.scalars.return_value.all.return_value = []
                m.scalar.return_value = 0
            return m

        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.side_effect = mock_conn_execute

        manifest = verify_record_level_correspondence(sqlite_path, mock_mgr, mode="clean")
        assert manifest["status"] == "VERIFIED"
        assert manifest["counts"]["approved_transformation"] == 1
        assert manifest["counts"]["exact_match"] == 0
        assert manifest["counts"]["matched"] == 1
        assert manifest["breakdown"]["incidents"]["approved_transformation"] == 1
        assert len(manifest["transformed_details"]) == 1
        assert manifest["transformed_details"][0]["id"] == "ZYLAR-INC-TRANSFORM-1"
    finally:
        _safe_unlink(sqlite_path)


def test_verify_clean_mode_rejects_target_only_records():
    """Confirms that clean import mode rejects extra/pre-existing records in PostgreSQL."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT, risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT, threat_intel TEXT, anomalous_events_count INTEGER)")
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        cur.execute("INSERT INTO incidents VALUES ('ZYLAR-INC-1', '2026-10-27T12:00:00Z', 'Phishing', 50, 'Medium', '[]', '{}', 1)")
        conn.commit()
        conn.close()

        inc_uuid = uuid.uuid4()
        pg_inc = IncidentModel(
            id=inc_uuid,
            incident_id="ZYLAR-INC-1",
            idempotency_key="legacy:ZYLAR-INC-1",
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            attack_classification="Phishing",
            risk_score=50,
            risk_category="Medium",
            mitigation_plan=[],
            threat_intel={},
            anomalous_events_count=1,
            status="NEW",
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = pg_inc
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        # Target database contains an extra incident "TARGET-ONLY-INCIDENT"
        def mock_conn_execute(q):
            m = MagicMock()
            q_str = str(q)
            if "incidents" in q_str:
                m.scalars.return_value.all.return_value = ["ZYLAR-INC-1", "TARGET-ONLY-INCIDENT"]
            elif "risk_history" in q_str:
                m.scalar.return_value = 0
            else:
                m.scalars.return_value.all.return_value = []
                m.scalar.return_value = 0
            return m

        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.side_effect = mock_conn_execute

        # Clean mode strictly requires target_only == 0
        with pytest.raises(MigrationVerificationError, match="Clean import verification failed: target database contains 1 target-only records"):
            verify_record_level_correspondence(sqlite_path, mock_mgr, mode="clean")

        # Merge mode permits target-only records, classifying and inventorying them
        manifest = verify_record_level_correspondence(sqlite_path, mock_mgr, mode="merge")
        assert manifest["status"] == "VERIFIED"
        assert manifest["counts"]["target_only"] == 1
        assert manifest["target_only"]["incidents_count"] == 1
        assert manifest["target_only"]["sample_target_only_incident_ids"] == ["TARGET-ONLY-INCIDENT"]
    finally:
        _safe_unlink(sqlite_path)


def test_verify_record_level_correspondence_detects_status_mismatch():
    """Confirms that mismatched incident status is detected during verification."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT, risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT, threat_intel TEXT, anomalous_events_count INTEGER, status TEXT)")
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        # SQLite has status 'resolved'
        cur.execute("INSERT INTO incidents VALUES ('ZYLAR-INC-STAT', '2026-10-27T12:00:00Z', 'Malware', 60, 'Medium', '[]', '{}', 1, 'resolved')")
        conn.commit()
        conn.close()

        # PG model has status 'NEW' (or OPEN)
        inc_uuid = uuid.uuid4()
        pg_inc = IncidentModel(
            id=inc_uuid,
            incident_id="ZYLAR-INC-STAT",
            idempotency_key="legacy:ZYLAR-INC-STAT",
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            attack_classification="Malware",
            risk_score=60,
            risk_category="Medium",
            mitigation_plan=[],
            threat_intel={},
            anomalous_events_count=1,
            status="NEW",
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = pg_inc
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        def mock_conn_execute(q):
            m = MagicMock()
            q_str = str(q)
            if "incidents" in q_str:
                m.scalars.return_value.all.return_value = ["ZYLAR-INC-STAT"]
            elif "risk_history" in q_str:
                m.scalar.return_value = 0
            else:
                m.scalars.return_value.all.return_value = []
                m.scalar.return_value = 0
            return m

        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.side_effect = mock_conn_execute

        with pytest.raises(MigrationVerificationError, match="status mismatch"):
            verify_record_level_correspondence(sqlite_path, mock_mgr, mode="merge")
    finally:
        _safe_unlink(sqlite_path)


def test_verify_record_level_correspondence_detects_ip_risk_score_mismatch():
    """Confirms that divergent last_risk_score for entity history raises MigrationVerificationError."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT, risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT, threat_intel TEXT, anomalous_events_count INTEGER)")
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        cur.execute("INSERT INTO ip_history VALUES ('10.10.10.10', 3, '2026-10-27T12:00:00Z', 85)")
        conn.commit()
        conn.close()

        # PG model has same offense_count (3) but divergent last_risk_score (40)
        pg_ip = IPHistoryModel(
            ip_address="10.10.10.10",
            offense_count=3,
            last_seen=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            last_risk_score=40,
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = pg_ip
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        def mock_conn_execute(q):
            m = MagicMock()
            q_str = str(q)
            if "ip_history" in q_str:
                m.scalars.return_value.all.return_value = ["10.10.10.10"]
            elif "risk_history" in q_str:
                m.scalar.return_value = 0
            else:
                m.scalars.return_value.all.return_value = []
                m.scalar.return_value = 0
            return m

        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.side_effect = mock_conn_execute

        with pytest.raises(MigrationVerificationError, match="last_risk_score mismatch"):
            verify_record_level_correspondence(sqlite_path, mock_mgr, mode="merge")
    finally:
        _safe_unlink(sqlite_path)


def test_verify_only_performs_no_writes():
    """Confirms that verify_record_level_correspondence never invokes write operations on session or engine."""
    import sqlite3

    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_path = Path(tf.name)
    tf.close()

    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, timestamp TEXT, attack_classification TEXT, risk_score INTEGER, risk_category TEXT, mitigation_plan TEXT, threat_intel TEXT, anomalous_events_count INTEGER)")
        cur.execute("CREATE TABLE ip_history (ip_address TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE user_history (username TEXT PRIMARY KEY, offense_count INTEGER, last_seen TEXT, last_risk_score INTEGER)")
        cur.execute("CREATE TABLE risk_history (id INTEGER PRIMARY KEY, timestamp TEXT, incident_id TEXT, risk_score INTEGER)")
        cur.execute("INSERT INTO incidents VALUES ('ZYLAR-INC-RO', '2026-10-27T12:00:00Z', 'Probe', 20, 'Low', '[]', '{}', 1)")
        conn.commit()
        conn.close()

        inc_uuid = uuid.uuid4()
        pg_inc = IncidentModel(
            id=inc_uuid,
            incident_id="ZYLAR-INC-RO",
            idempotency_key="legacy:ZYLAR-INC-RO",
            timestamp=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
            attack_classification="Probe",
            risk_score=20,
            risk_category="Low",
            mitigation_plan=[],
            threat_intel={},
            anomalous_events_count=1,
            status="NEW",
        )

        mock_mgr = MagicMock()
        mock_session = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = pg_inc
        mock_mgr.get_session.return_value.__enter__.return_value = mock_session

        def mock_conn_execute(q):
            m = MagicMock()
            q_str = str(q)
            if "incidents" in q_str:
                m.scalars.return_value.all.return_value = ["ZYLAR-INC-RO"]
            elif "risk_history" in q_str:
                m.scalar.return_value = 0
            else:
                m.scalars.return_value.all.return_value = []
                m.scalar.return_value = 0
            return m

        mock_mgr.engine.connect.return_value.__enter__.return_value.execute.side_effect = mock_conn_execute

        verify_record_level_correspondence(sqlite_path, mock_mgr, mode="clean")

        # Session write methods must NEVER be called
        mock_session.add.assert_not_called()
        mock_session.add_all.assert_not_called()
        mock_session.delete.assert_not_called()
        mock_session.commit.assert_not_called()
        mock_session.flush.assert_not_called()
    finally:
        _safe_unlink(sqlite_path)
