from __future__ import annotations

import concurrent.futures
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, func, select, text

from zylar.core.settings import get_settings
from zylar.persistence.database import DatabaseManager
from zylar.persistence.dtos import EventRefData, IncidentCreate
from zylar.persistence.exceptions import (
    IdempotencyConflictError,
)
from zylar.persistence.models import (
    AuditLogModel,
    IncidentEventRefModel,
    IncidentModel,
    IPHistoryModel,
    RiskHistoryModel,
    UserHistoryModel,
)
from zylar.persistence.repositories import (
    IncidentRepository,
    OffenderHistoryRepository,
)
from zylar.persistence.unit_of_work import UnitOfWork


def check_postgres_availability() -> tuple[bool, str]:
    settings = get_settings()
    try:
        engine = create_engine(str(settings.database_url), connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True, ""
    except Exception as exc:
        return False, str(exc)


_IS_STRICT = os.environ.get("ZYLAR_REQUIRE_POSTGRES", "").strip().lower() in (
    "1",
    "true",
    "yes",
) or os.environ.get("CI", "").strip().lower() in ("1", "true", "yes")
_PG_AVAILABLE, _PG_ERROR = check_postgres_availability()

pytestmark = pytest.mark.skipif(
    not _IS_STRICT and not _PG_AVAILABLE,
    reason=f"PostgreSQL not reachable at configured ZYLAR_DATABASE_URL ({_PG_ERROR})",
)


@pytest.fixture(scope="module", autouse=True)
def enforce_postgres_availability():
    if _IS_STRICT and not _PG_AVAILABLE:
        pytest.fail(
            f"Strict verification mode enabled (ZYLAR_REQUIRE_POSTGRES/CI), but PostgreSQL is unreachable at configured ZYLAR_DATABASE_URL: {_PG_ERROR}"
        )


@pytest.fixture(scope="module")
def db_manager():
    settings = get_settings()
    mgr = DatabaseManager(settings)
    try:
        yield mgr
    finally:
        mgr.dispose()


@pytest.fixture(scope="module")
def session_factory(db_manager):
    return db_manager.session_factory


@pytest.fixture(autouse=True)
def clean_postgres_test_data(db_manager):
    """Cleans up any test-prefixed records before and after each test."""

    def cleanup():
        with db_manager.engine.connect() as conn:
            with conn.begin():
                conn.execute(
                    text(
                        "DELETE FROM audit_logs WHERE actor LIKE 'test-%' OR correlation_id LIKE 'test-%'"
                    )
                )
                conn.execute(
                    text(
                        "DELETE FROM incidents WHERE incident_id LIKE 'ZYLAR-INC-TEST-%' OR idempotency_key LIKE 'test-%'"
                    )
                )
                conn.execute(
                    text(
                        "DELETE FROM ip_history WHERE ip_address IN ('198.51.100.10', '198.51.100.55', '198.51.100.77', '198.51.100.99') OR ip_address LIKE '203.0.113.%'"
                    )
                )
                conn.execute(text("DELETE FROM user_history WHERE username LIKE 'test_user_%'"))
                conn.execute(text("DELETE FROM dead_letter_events WHERE stream_id LIKE 'test-%'"))
                conn.execute(
                    text("DELETE FROM ingestion_checkpoints WHERE stream_id LIKE 'test-%'")
                )

    cleanup()
    yield
    cleanup()


def make_test_incident(
    key_suffix: str,
    risk_score: int = 70,
    classification: str = "Credential Access",
    ip: str = "198.51.100.10",
    user: str = "test_user_1",
    mitigation_plan: list[str] | None = None,
    threat_intel: dict[str, Any] | None = None,
    event_refs: list[EventRefData] | None = None,
) -> IncidentCreate:
    now = datetime.now(UTC)
    refs = (
        event_refs
        if event_refs is not None
        else [
            EventRefData(
                event_source="zeek",
                source_event_id=f"evt-{key_suffix}",
                raw_event_hash=f"hash-{key_suffix}",
                event_timestamp=now,
                source_ip=ip,
                destination_port=443,
                user_identifier=user,
            )
        ]
    )
    return IncidentCreate(
        incident_id=f"ZYLAR-INC-TEST-{key_suffix.upper()}",
        idempotency_key=f"test-idemp-{key_suffix}",
        timestamp=now,
        attack_classification=classification,
        risk_score=risk_score,
        risk_category="High" if risk_score >= 70 else "Medium",
        mitigation_plan=mitigation_plan
        if mitigation_plan is not None
        else ["Isolate host", "Revoke credentials"],
        threat_intel=threat_intel if threat_intel is not None else {"ttp": "T1110"},
        anomalous_events_count=len(refs),
        status="NEW",
        event_refs=refs,
        actor="test-agent",
        correlation_id=f"test-corr-{key_suffix}",
    )


def test_postgres_incident_crud_and_relationships(session_factory):
    suffix = uuid.uuid4().hex[:8]
    create_dto = make_test_incident(suffix)

    with UnitOfWork(session_factory) as uow:
        result = uow.incidents.create_incident(create_dto)
        assert result.created is True
        assert result.incident.incident_id == create_dto.incident_id

    # Verify persistence in a separate session
    session = session_factory()
    try:
        repo = IncidentRepository(session)
        incident_by_id = repo.get_by_incident_id(create_dto.incident_id)
        assert incident_by_id is not None
        assert incident_by_id.risk_score == 70
        assert incident_by_id.attack_classification == "Credential Access"

        # Verify event references
        assert len(incident_by_id.event_refs) == 1
        assert incident_by_id.event_refs[0].source_event_id == f"evt-{suffix}"

        # Verify risk history
        assert len(incident_by_id.risk_records) == 1
        assert incident_by_id.risk_records[0].risk_score == 70

        # Verify audit record
        assert len(incident_by_id.audit_records) == 1
        assert incident_by_id.audit_records[0].action == "INCIDENT_CREATED"

        # Verify idempotency lookup
        by_key = repo.get_by_idempotency_key(create_dto.idempotency_key)
        assert by_key is not None
        assert by_key.id == incident_by_id.id
    finally:
        session.close()


def test_postgres_incident_update_status(session_factory):
    suffix = uuid.uuid4().hex[:8]
    create_dto = make_test_incident(suffix)

    with UnitOfWork(session_factory) as uow:
        uow.incidents.create_incident(create_dto)

    # Update status to INVESTIGATING
    with UnitOfWork(session_factory) as uow:
        updated = uow.incidents.update_status(
            incident_id=create_dto.incident_id,
            new_status="INVESTIGATING",
            actor="test-analyst-bob",
            correlation_id=f"test-corr-status-{suffix}",
            reason="Confirmed malicious activity",
        )
        assert updated.status == "INVESTIGATING"

    # Verify updated status and audit trail
    session = session_factory()
    try:
        repo = IncidentRepository(session)
        incident = repo.get_by_incident_id(create_dto.incident_id)
        assert incident is not None
        assert incident.status == "INVESTIGATING"

        # There should now be 2 audit logs (creation + status change)
        assert len(incident.audit_records) == 2
        status_audit = [a for a in incident.audit_records if a.action == "STATUS_CHANGE"][0]
        assert status_audit.actor == "test-analyst-bob"
        assert status_audit.details["old_status"] == "NEW"
        assert status_audit.details["new_status"] == "INVESTIGATING"
    finally:
        session.close()


def test_postgres_idempotency_exact_duplicate(session_factory):
    suffix = uuid.uuid4().hex[:8]
    dto1 = make_test_incident(suffix)
    dto2 = make_test_incident(suffix)  # identical payload and key

    with UnitOfWork(session_factory) as uow:
        res1 = uow.incidents.create_incident(dto1)
        assert res1.created is True

    # Replay identical request
    with UnitOfWork(session_factory) as uow:
        res2 = uow.incidents.create_incident(dto2)
        assert res2.created is False
        assert res2.incident.id == res1.incident.id

    # Verify row count in incidents is strictly 1
    session = session_factory()
    try:
        stmt = select(IncidentModel).where(IncidentModel.idempotency_key == dto1.idempotency_key)
        all_matches = session.execute(stmt).scalars().all()
        assert len(all_matches) == 1
    finally:
        session.close()


def test_postgres_idempotency_conflicting_payload_raises(session_factory):
    suffix = uuid.uuid4().hex[:8]
    dto1 = make_test_incident(suffix, risk_score=50, classification="Reconnaissance")

    with UnitOfWork(session_factory) as uow:
        res1 = uow.incidents.create_incident(dto1)
        assert res1.created is True

    # Same idempotency key, but mismatched risk_score and classification
    dto_conflicting = make_test_incident(suffix, risk_score=95, classification="Exfiltration")

    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(dto_conflicting)


def test_postgres_idempotency_conflicting_mitigation_plan_raises(session_factory):
    """Confirms that modifying the mitigation plan for the same idempotency key raises IdempotencyConflictError."""
    suffix = uuid.uuid4().hex[:8]
    dto1 = make_test_incident(suffix, mitigation_plan=["Block IP"])

    with UnitOfWork(session_factory) as uow:
        res1 = uow.incidents.create_incident(dto1)
        assert res1.created is True

    # Same key, changed mitigation_plan
    dto_conflicting = make_test_incident(
        suffix, mitigation_plan=["Block IP", "Isolate host subnet"]
    )

    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(dto_conflicting)


def test_postgres_idempotency_conflicting_threat_intel_raises(session_factory):
    """Confirms that modifying threat intelligence for the same idempotency key raises IdempotencyConflictError."""
    suffix = uuid.uuid4().hex[:8]
    dto1 = make_test_incident(suffix, threat_intel={"reputation": "malicious"})

    with UnitOfWork(session_factory) as uow:
        res1 = uow.incidents.create_incident(dto1)
        assert res1.created is True

    # Same key, changed threat_intel
    dto_conflicting = make_test_incident(
        suffix, threat_intel={"reputation": "malicious", "cve": "CVE-2026-1234"}
    )

    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(dto_conflicting)


def test_postgres_idempotency_conflicting_event_refs_raises(session_factory):
    """Confirms that altering constituent event references raises IdempotencyConflictError."""
    suffix = uuid.uuid4().hex[:8]
    now = datetime.now(UTC)
    ref1 = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}-A",
        raw_event_hash=f"hash-{suffix}-A",
        event_timestamp=now,
    )
    dto1 = make_test_incident(suffix, event_refs=[ref1])

    with UnitOfWork(session_factory) as uow:
        res1 = uow.incidents.create_incident(dto1)
        assert res1.created is True

    # Same key, divergent event references
    ref2 = EventRefData(
        event_source="suricata",
        source_event_id=f"evt-{suffix}-B",
        raw_event_hash=f"hash-{suffix}-B",
        event_timestamp=now,
    )
    dto_conflicting = make_test_incident(suffix, event_refs=[ref2])

    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(dto_conflicting)


def test_postgres_idempotency_replay_does_not_increment_recurrence(session_factory):
    """Verifies that replaying the identical canonical batch does not increment offense or risk counts."""
    suffix = uuid.uuid4().hex[:8]
    dto = make_test_incident(suffix, ip="198.51.100.10", user="test_user_1")

    # Initial creation via UnitOfWork.persist_incident_lifecycle
    with UnitOfWork(session_factory) as uow:
        res1 = uow.persist_incident_lifecycle(dto)
        assert res1.created is True

    # Read baseline counts
    session = session_factory()
    try:
        ip_row1 = session.execute(
            select(IPHistoryModel).where(IPHistoryModel.ip_address == "198.51.100.10")
        ).scalar_one()
        user_row1 = session.execute(
            select(UserHistoryModel).where(UserHistoryModel.username == "test_user_1")
        ).scalar_one()
        risk_count1 = (
            session.execute(
                select(func.count(RiskHistoryModel.id)).where(
                    RiskHistoryModel.incident_id == res1.incident.id
                )
            ).scalar()
            or 0
        )
        ip_offenses_1 = ip_row1.offense_count
        user_offenses_1 = user_row1.offense_count
    finally:
        session.close()

    # Replay the identical incident via persist_incident_lifecycle
    with UnitOfWork(session_factory) as uow:
        res2 = uow.persist_incident_lifecycle(dto)
        assert res2.created is False
        assert res2.incident.id == res1.incident.id

    # Confirm recurrence counts and risk records did NOT increment
    session = session_factory()
    try:
        ip_row2 = session.execute(
            select(IPHistoryModel).where(IPHistoryModel.ip_address == "198.51.100.10")
        ).scalar_one()
        user_row2 = session.execute(
            select(UserHistoryModel).where(UserHistoryModel.username == "test_user_1")
        ).scalar_one()
        risk_count2 = (
            session.execute(
                select(func.count(RiskHistoryModel.id)).where(
                    RiskHistoryModel.incident_id == res1.incident.id
                )
            ).scalar()
            or 0
        )

        assert ip_row2.offense_count == ip_offenses_1
        assert user_row2.offense_count == user_offenses_1
        assert risk_count2 == risk_count1
    finally:
        session.close()


def test_postgres_uow_atomic_rollback_on_failure(session_factory):
    suffix = uuid.uuid4().hex[:8]
    dto = make_test_incident(suffix)

    # Start UnitOfWork and intentionally raise an exception mid-operation
    with pytest.raises(RuntimeError, match="simulated failure"):
        with UnitOfWork(session_factory) as uow:
            uow.incidents.create_incident(dto)
            raise RuntimeError("simulated failure after incident creation")

    # Verify that the incident, event refs, risk records, and audit logs were all rolled back
    session = session_factory()
    try:
        repo = IncidentRepository(session)
        assert repo.get_by_incident_id(dto.incident_id) is None

        # Verify no orphan event refs
        orphans = (
            session.execute(
                select(IncidentEventRefModel).where(
                    IncidentEventRefModel.source_event_id == f"evt-{suffix}"
                )
            )
            .scalars()
            .all()
        )
        assert len(orphans) == 0
    finally:
        session.close()


def test_postgres_offender_history_atomic_upsert(session_factory):
    test_ip = "198.51.100.77"
    test_user = "test_user_upsert"
    now = datetime.now(UTC)

    # First offense
    with UnitOfWork(session_factory) as uow:
        uow.offenders.record_offenses([test_ip], [test_user], risk_score=60, timestamp=now)

    session = session_factory()
    try:
        repo = OffenderHistoryRepository(session)
        ip_rec = repo.get_ip_history(test_ip)
        assert ip_rec is not None
        assert ip_rec.offense_count == 1
        assert ip_rec.last_risk_score == 60

        user_rec = repo.get_user_history(test_user)
        assert user_rec is not None
        assert user_rec.offense_count == 1

        factor = repo.get_recurrence_factor([test_ip], [test_user])
        # 2 total offenses (1 IP + 1 User) * 5 = 10
        assert factor == 10
    finally:
        session.close()

    # Second offense for the same IP and user
    with UnitOfWork(session_factory) as uow:
        uow.offenders.record_offenses([test_ip], [test_user], risk_score=85, timestamp=now)

    session = session_factory()
    try:
        repo = OffenderHistoryRepository(session)
        ip_rec = repo.get_ip_history(test_ip)
        assert ip_rec is not None
        assert ip_rec.offense_count == 2
        assert ip_rec.last_risk_score == 85

        factor = repo.get_recurrence_factor([test_ip], [test_user])
        # 4 total offenses (2 IP + 2 User) * 5 = 20
        assert factor == 20
    finally:
        session.close()


def test_postgres_concurrent_offender_updates(session_factory):
    """Spawns 5 concurrent threads updating the same IP 4 times each.

    Ensures no updates are lost under concurrent writes: final offense count must be 20.
    """
    target_ip = "198.51.100.99"
    now = datetime.now(UTC)

    def worker_update():
        for _ in range(4):
            with UnitOfWork(session_factory) as uow:
                uow.offenders.record_offenses([target_ip], [], risk_score=50, timestamp=now)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker_update) for _ in range(5)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    session = session_factory()
    try:
        repo = OffenderHistoryRepository(session)
        ip_rec = repo.get_ip_history(target_ip)
        assert ip_rec is not None
        assert ip_rec.offense_count == 20
    finally:
        session.close()


def test_postgres_concurrent_idempotency_inserts(session_factory):
    """Spawns 4 concurrent threads trying to insert the exact same incident.

    PostgreSQL's unique constraint + repository savepoint handling must guarantee:
    - Exactly one thread returns created=True
    - All other threads return created=False
    - Zero crashes or aborted transaction errors
    - Strictly 1 row in the database
    """
    suffix = uuid.uuid4().hex[:8]
    dto = make_test_incident(suffix)

    def worker_insert():
        with UnitOfWork(session_factory) as uow:
            return uow.incidents.create_incident(dto)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker_insert) for _ in range(4)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    created_flags = [r.created for r in results]
    assert created_flags.count(True) == 1
    assert created_flags.count(False) == 3

    # Verify single row persisted
    session = session_factory()
    try:
        repo = IncidentRepository(session)
        incident = repo.get_by_idempotency_key(f"test-idemp-{suffix}")
        assert incident is not None
    finally:
        session.close()


def test_postgres_uow_avoids_incrementing_offender_on_duplicate(session_factory):
    suffix = uuid.uuid4().hex[:8]
    test_ip = "198.51.100.55"
    test_user = "test_user_no_dup"
    dto = make_test_incident(suffix, ip=test_ip, user=test_user)

    # Initial creation
    with UnitOfWork(session_factory) as uow:
        res1 = uow.persist_incident_lifecycle(dto)
        assert res1.created is True

    session = session_factory()
    try:
        repo = OffenderHistoryRepository(session)
        assert repo.get_ip_history(test_ip).offense_count == 1
    finally:
        session.close()

    # Replay duplicate
    with UnitOfWork(session_factory) as uow:
        res2 = uow.persist_incident_lifecycle(dto)
        assert res2.created is False

    session = session_factory()
    try:
        repo = OffenderHistoryRepository(session)
        # MUST STILL BE 1: duplicate replays must not increment offender history!
        assert repo.get_ip_history(test_ip).offense_count == 1
    finally:
        session.close()


def test_postgres_idempotency_individual_event_ref_fields_and_multiplicity(session_factory):
    """Verifies that altering ANY individual event-reference field or multiplicity raises IdempotencyConflictError."""
    suffix = uuid.uuid4().hex[:8]
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)

    base_ref = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now,
        source_ip="10.0.0.1",
        destination_port=443,
        user_identifier="alice",
    )
    dto_base = make_test_incident(suffix, event_refs=[base_ref])

    with UnitOfWork(session_factory) as uow:
        res = uow.incidents.create_incident(dto_base)
        assert res.created is True

    # 1. Changing event_source individually raises IdempotencyConflictError
    ref_changed_src = EventRefData(
        event_source="suricata",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now,
        source_ip="10.0.0.1",
        destination_port=443,
        user_identifier="alice",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_src]))

    # 2. Changing source_event_id individually raises IdempotencyConflictError
    ref_changed_eid = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}-other",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now,
        source_ip="10.0.0.1",
        destination_port=443,
        user_identifier="alice",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_eid]))

    # 3. Changing raw_event_hash individually raises IdempotencyConflictError
    ref_changed_hash = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}-different",
        event_timestamp=now,
        source_ip="10.0.0.1",
        destination_port=443,
        user_identifier="alice",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_hash]))

    # 4. Changing event_timestamp individually raises IdempotencyConflictError
    ref_changed_ts = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now + timedelta(seconds=60),
        source_ip="10.0.0.1",
        destination_port=443,
        user_identifier="alice",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_ts]))

    # 5. Changing source_ip individually raises IdempotencyConflictError
    ref_changed_ip = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now,
        source_ip="10.0.0.99",
        destination_port=443,
        user_identifier="alice",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_ip]))

    # 6. Changing destination_port individually raises IdempotencyConflictError
    ref_changed_port = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now,
        source_ip="10.0.0.1",
        destination_port=8443,
        user_identifier="alice",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_port]))

    # 7. Changing user_identifier individually raises IdempotencyConflictError
    ref_changed_user = EventRefData(
        event_source="zeek",
        source_event_id=f"evt-{suffix}",
        raw_event_hash=f"hash-{suffix}",
        event_timestamp=now,
        source_ip="10.0.0.1",
        destination_port=443,
        user_identifier="mallory",
    )
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(make_test_incident(suffix, event_refs=[ref_changed_user]))

    # 8. Changing multiplicity (e.g. duplicate reference) raises IdempotencyConflictError
    dto_multiplicity = make_test_incident(suffix, event_refs=[base_ref, base_ref])
    with UnitOfWork(session_factory) as uow:
        with pytest.raises(IdempotencyConflictError, match="payload mismatch"):
            uow.incidents.create_incident(dto_multiplicity)

    # 9. Exact identical replay returns created=False and existing incident
    dto_replay = make_test_incident(suffix, event_refs=[base_ref])
    with UnitOfWork(session_factory) as uow:
        res_replay = uow.incidents.create_incident(dto_replay)
        assert res_replay.created is False
        assert res_replay.incident.id == res.incident.id


def test_postgres_idempotency_replay_without_event_id_stable_hash(session_factory):
    """Verifies that an event without an upstream event_id derives a stable deterministic reference ID and replays cleanly."""
    suffix = uuid.uuid4().hex[:8]
    stable_hash = f"hash-{suffix}-deterministic"
    derived_id = f"evt-suricata-{stable_hash[:16]}"
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)

    ref = EventRefData(
        event_source="suricata",
        source_event_id=derived_id,
        raw_event_hash=stable_hash,
        event_timestamp=now,
        source_ip="10.0.0.5",
        destination_port=80,
        user_identifier="test_user",
    )
    dto = make_test_incident(suffix, event_refs=[ref])

    with UnitOfWork(session_factory) as uow:
        res1 = uow.incidents.create_incident(dto)
        assert res1.created is True

    # Replay with identical derived reference
    with UnitOfWork(session_factory) as uow:
        res2 = uow.incidents.create_incident(dto)
        assert res2.created is False
        assert res2.incident.id == res1.incident.id


def test_postgres_idempotency_replay_does_not_increment_audit_records(session_factory):
    """Verifies that duplicate replay never creates duplicate audit log records."""
    suffix = uuid.uuid4().hex[:8]
    dto = make_test_incident(suffix)

    # Initial creation
    with UnitOfWork(session_factory) as uow:
        res1 = uow.persist_incident_lifecycle(dto)
        assert res1.created is True

    session = session_factory()
    try:
        audit_count_before = (
            session.execute(
                select(func.count(AuditLogModel.id)).where(
                    AuditLogModel.incident_id == res1.incident.id
                )
            ).scalar()
            or 0
        )
        assert audit_count_before > 0
    finally:
        session.close()

    # Replay identical incident
    with UnitOfWork(session_factory) as uow:
        res2 = uow.persist_incident_lifecycle(dto)
        assert res2.created is False

    session = session_factory()
    try:
        audit_count_after = (
            session.execute(
                select(func.count(AuditLogModel.id)).where(
                    AuditLogModel.incident_id == res1.incident.id
                )
            ).scalar()
            or 0
        )
        assert audit_count_after == audit_count_before
    finally:
        session.close()
