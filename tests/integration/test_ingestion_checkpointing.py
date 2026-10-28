from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from sqlalchemy import create_engine, func, select, text

from zylar.core.settings import get_settings
from zylar.ingestion.engine import CheckpointedIngestionWorker
from zylar.persistence.database import DatabaseManager
from zylar.persistence.dtos import EventRefData, IncidentCreate
from zylar.persistence.models import (
    DeadLetterEventModel,
    IncidentModel,
    IPHistoryModel,
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


_IS_STRICT = (
    os.environ.get("ZYLAR_REQUIRE_POSTGRES", "").strip().lower() in ("1", "true", "yes")
    or os.environ.get("CI", "").strip().lower() in ("1", "true", "yes")
)
_PG_AVAILABLE, _PG_ERROR = check_postgres_availability()

pytestmark = pytest.mark.skipif(
    not _IS_STRICT and not _PG_AVAILABLE,
    reason=f"PostgreSQL not reachable at configured ZYLAR_DATABASE_URL ({_PG_ERROR})",
)


@pytest.fixture(scope="module", autouse=True)
def enforce_postgres_availability():
    if _IS_STRICT and not _PG_AVAILABLE:
        pytest.fail(
            f"Strict verification mode enabled (ZYLAR_REQUIRE_POSTGRES/CI), but PostgreSQL is unreachable: {_PG_ERROR}"
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
def clean_checkpoint_test_data(db_manager):
    """Cleans up any test-prefixed records before and after each test."""

    def cleanup():
        with db_manager.engine.connect() as conn:
            with conn.begin():
                conn.execute(text("DELETE FROM audit_logs WHERE actor LIKE 'test-%' OR correlation_id LIKE 'test-%'"))
                conn.execute(text("DELETE FROM incidents WHERE incident_id LIKE 'ZYLAR-INC-TEST-%' OR idempotency_key LIKE 'test-%'"))
                conn.execute(text("DELETE FROM ip_history WHERE ip_address LIKE '198.51.100.%' OR ip_address LIKE '203.0.113.%'"))
                conn.execute(text("DELETE FROM user_history WHERE username LIKE 'test_user_%'"))
                conn.execute(text("DELETE FROM dead_letter_events WHERE stream_id LIKE 'test-%'"))
                conn.execute(text("DELETE FROM ingestion_checkpoints WHERE stream_id LIKE 'test-%'"))

    cleanup()
    yield
    cleanup()


def test_worker_resumes_from_last_committed_checkpoint(session_factory):
    stream_id = "test-stream-resume"
    t0 = datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    t2 = t0 + timedelta(seconds=20)

    # Pre-seed initial checkpoint
    with UnitOfWork(session_factory) as uow:
        uow.checkpoints.get_or_create(stream_id, default_start_time=t0)
        uow.checkpoints.advance_checkpoint(
            stream_id=stream_id,
            new_timestamp=t1,
            last_id="doc-02",
            processed_count=2,
        )
        uow.commit()

    # Worker 2 starts up
    mock_es = MagicMock()
    # ES returns docs: doc-01 (t0), doc-02 (t1), doc-03 (t2)
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {"_id": "doc-01", "_source": {"timestamp": t0.isoformat(), "source_ip": "198.51.100.10"}},
                {"_id": "doc-02", "_source": {"timestamp": t1.isoformat(), "source_ip": "198.51.100.11"}},
                {"_id": "doc-03", "_source": {"timestamp": t2.isoformat(), "source_ip": "198.51.100.12"}},
            ]
        }
    }

    mock_workflow = MagicMock(return_value={})
    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="test-worker-restart",
        es_client=mock_es,
        session_factory=session_factory,
        workflow_invoker=mock_workflow,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "SUCCESS"
    assert result.events_read == 3
    # Exactly 1 event processed (doc-03) because doc-01 and doc-02 are <= committed checkpoint
    assert result.events_processed == 1
    assert result.checkpoint_id == "doc-03"
    assert result.checkpoint_timestamp == t2

    # Verify state in PostgreSQL
    with UnitOfWork(session_factory) as uow:
        cp = uow.checkpoints.get(stream_id)
        assert cp is not None
        assert cp.last_processed_timestamp == t2
        assert cp.last_processed_id == "doc-03"
        assert cp.batch_sequence == 2
        assert cp.events_processed_count == 3


def test_replaying_identical_batch_causes_zero_duplicate_incidents_and_zero_recurrence_increments(session_factory):
    stream_id = "test-stream-replay"
    t0 = datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)

    raw_event = {
        "_id": "doc-replay-01",
        "timestamp": t0.isoformat(),
        "source": "suricata",
        "source_ip": "198.51.100.50",
        "user_identifier": "test_user_replay",
        "raw_event_hash": "a" * 64,
    }

    def workflow_persister(state):
        with UnitOfWork(session_factory) as uow:
            dto = IncidentCreate(
                incident_id="ZYLAR-INC-TEST-REPLAY",
                idempotency_key="test-key-replay-deterministic",
                timestamp=t0,
                attack_classification="Reconnaissance",
                risk_score=75,
                risk_category="High",
                mitigation_plan=["Block IP"],
                threat_intel={},
                anomalous_events_count=1,
                status="NEW",
                event_refs=[
                    EventRefData(
                        event_source="suricata",
                        source_event_id="doc-replay-01",
                        raw_event_hash="a" * 64,
                        event_timestamp=t0,
                        source_ip="198.51.100.50",
                        user_identifier="test_user_replay",
                    )
                ],
                actor="test-ingestion",
                correlation_id="test-corr-replay",
            )
            uow.persist_incident_lifecycle(
                dto,
                source_ips=["198.51.100.50"],
                user_identifiers=["test_user_replay"],
            )
            uow.commit()
        return {}

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": [{"_id": "doc-replay-01", "_source": raw_event}]}}

    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="test-worker-1",
        es_client=mock_es,
        session_factory=session_factory,
        workflow_invoker=workflow_persister,
    )

    # 1. First run: creates incident and records offense
    res1 = worker.poll_and_process_batch()
    assert res1.status == "SUCCESS"
    assert res1.events_processed == 1

    with UnitOfWork(session_factory) as uow:
        incident_stmt = select(func.count(IncidentModel.id)).where(IncidentModel.idempotency_key == "test-key-replay-deterministic")
        assert uow.session.execute(incident_stmt).scalar() == 1

        ip_stmt = select(IPHistoryModel).where(IPHistoryModel.ip_address == "198.51.100.50")
        ip_row = uow.session.execute(ip_stmt).scalar_one()
        assert ip_row.offense_count == 1

    # 2. Simulate upstream replay of identical batch (e.g. resetting watermark or redelivered message)
    with UnitOfWork(session_factory) as uow:
        # Reset watermark back to t0 - 1s to simulate replay
        cp = uow.checkpoints.get(stream_id)
        cp.last_processed_timestamp = t0 - timedelta(seconds=1)
        cp.last_processed_id = None
        uow.commit()

    res2 = worker.poll_and_process_batch()
    assert res2.status == "SUCCESS"

    # Verify: ZERO duplicate incidents and ZERO recurrence increments
    with UnitOfWork(session_factory) as uow:
        incidents_count = uow.session.execute(incident_stmt).scalar()
        assert incidents_count == 1  # exactly 1 incident, no duplicates!

        ip_row_after = uow.session.execute(ip_stmt).scalar_one()
        assert ip_row_after.offense_count == 1  # unchanged recurrence count!


def test_interruption_during_processing_preserves_unadvanced_checkpoint(session_factory):
    stream_id = "test-stream-crash"
    t_start = datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)

    # Initialize checkpoint at t_start
    with UnitOfWork(session_factory) as uow:
        uow.checkpoints.get_or_create(stream_id, default_start_time=t_start)
        uow.commit()

    def crashing_workflow(state):
        raise RuntimeError("Database connection dropped during workflow!")

    mock_es = MagicMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-crash-01",
                    "_source": {
                        "timestamp": (t_start + timedelta(seconds=15)).isoformat(),
                        "source_ip": "198.51.100.99",
                    },
                }
            ]
        }
    }

    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="test-worker-crash",
        es_client=mock_es,
        session_factory=session_factory,
        workflow_invoker=crashing_workflow,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "TRANSIENT_FAILURE"
    assert result.events_processed == 0

    # Verify checkpoint did NOT advance in PostgreSQL
    with UnitOfWork(session_factory) as uow:
        cp = uow.checkpoints.get(stream_id)
        assert cp is not None
        assert cp.last_processed_timestamp == t_start
        assert cp.last_processed_id is None
        assert cp.retry_count == 1
        assert cp.status == "RETRYING"
        assert "Database connection dropped" in (cp.last_error or "")


def test_poison_pill_event_quarantined_and_batch_proceeds(session_factory):
    stream_id = "test-stream-poison"
    t_start = datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)
    t_valid = t_start + timedelta(seconds=30)

    with UnitOfWork(session_factory) as uow:
        uow.checkpoints.get_or_create(stream_id, default_start_time=t_start)
        uow.commit()

    mock_es = MagicMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-corrupt",
                    "_source": {"timestamp": "INVALID_CORRUPT_TIMESTAMP_DATA", "source_ip": "1.2.3.4"},
                },
                {
                    "_id": "doc-valid-1",
                    "_source": {"timestamp": t_valid.isoformat(), "source_ip": "198.51.100.77"},
                },
            ]
        }
    }

    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="test-worker-poison",
        es_client=mock_es,
        session_factory=session_factory,
        workflow_invoker=lambda state: {},
    )

    result = worker.poll_and_process_batch()
    assert result.status == "SUCCESS"
    assert result.events_read == 2
    assert result.events_processed == 1
    assert result.dead_letters_count == 1
    assert result.checkpoint_id == "doc-valid-1"
    assert result.checkpoint_timestamp == t_valid

    # Check dead_letter_events in PostgreSQL
    with UnitOfWork(session_factory) as uow:
        dl_stmt = select(DeadLetterEventModel).where(DeadLetterEventModel.stream_id == stream_id)
        quarantined = uow.session.execute(dl_stmt).scalars().all()
        assert len(quarantined) == 1
        assert quarantined[0].event_id == "doc-corrupt"
        assert quarantined[0].error_reason == "MALFORMED_TIMESTAMP"
        assert len(quarantined[0].raw_event_hash) == 64
        assert quarantined[0].status == "QUARANTINED"

        # Checkpoint advanced past the batch
        cp = uow.checkpoints.get(stream_id)
        assert cp.last_processed_timestamp == t_valid
        assert cp.last_processed_id == "doc-valid-1"


def test_transient_elasticsearch_failure_and_recovery(session_factory):
    stream_id = "test-stream-es-recovery"
    t_start = datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)

    with UnitOfWork(session_factory) as uow:
        uow.checkpoints.get_or_create(stream_id, default_start_time=t_start)
        uow.commit()

    mock_es = MagicMock()
    mock_es.search.side_effect = ESConnectionError("ES cluster unavailable")

    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="test-worker-es",
        es_client=mock_es,
        session_factory=session_factory,
        workflow_invoker=lambda state: {},
    )

    # 1. Transient failure
    res1 = worker.poll_and_process_batch()
    assert res1.status == "TRANSIENT_FAILURE"
    assert res1.retry_count == 1

    with UnitOfWork(session_factory) as uow:
        cp = uow.checkpoints.get(stream_id)
        assert cp.retry_count == 1
        assert cp.status == "RETRYING"

    # 2. ES recovers
    t_new = t_start + timedelta(seconds=10)
    mock_es.search.side_effect = None
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {"_id": "doc-recovered-01", "_source": {"timestamp": t_new.isoformat()}}
            ]
        }
    }

    res2 = worker.poll_and_process_batch()
    assert res2.status == "SUCCESS"
    assert res2.events_processed == 1

    # Verify retry count is reset to 0 in PostgreSQL
    with UnitOfWork(session_factory) as uow:
        cp_recovered = uow.checkpoints.get(stream_id)
        assert cp_recovered.retry_count == 0
        assert cp_recovered.last_error is None
        assert cp_recovered.last_processed_timestamp == t_new


def test_concurrent_worker_leasing_exclusion(session_factory):
    stream_id = "test-stream-lease-exclusive"
    t_start = datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)

    with UnitOfWork(session_factory) as uow:
        uow.checkpoints.get_or_create(stream_id, default_start_time=t_start)
        uow.commit()

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": []}}

    worker_a = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="worker-A",
        es_client=mock_es,
        session_factory=session_factory,
        lease_duration_seconds=60,
    )
    worker_b = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id="worker-B",
        es_client=mock_es,
        session_factory=session_factory,
        lease_duration_seconds=60,
    )

    assert worker_a.worker_id == "worker-A"
    assert worker_b.worker_id == "worker-B"

    # Worker A acquires lease
    with UnitOfWork(session_factory) as uow:
        acquired_a = uow.checkpoints.acquire_lease(stream_id, "worker-A", lease_seconds=60)
        assert acquired_a is True
        uow.commit()

    # Worker B tries to poll -> must fail lease acquisition and yield
    res_b = worker_b.poll_and_process_batch()
    assert res_b.status == "LEASE_NOT_ACQUIRED"
    assert res_b.events_processed == 0

    # Worker A releases lease
    with UnitOfWork(session_factory) as uow:
        uow.checkpoints.release_lease(stream_id, "worker-A")
        uow.commit()

    # Now Worker B can acquire lease
    res_b_after = worker_b.poll_and_process_batch()
    assert res_b_after.status in ("IDLE", "SUCCESS")
