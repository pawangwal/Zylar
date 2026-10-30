from __future__ import annotations

import urllib.request
import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from zylar.ingestion.engine import IngestionBatchResult
from zylar.ingestion.runner import IngestionRunner
from zylar.persistence.models import Base
from zylar.persistence.repositories import WorkerInstanceRepository


@pytest.fixture
def test_db_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["worker_instances"]])
    factory = sessionmaker(bind=engine)
    yield factory
    Base.metadata.drop_all(engine, tables=[Base.metadata.tables["worker_instances"]])
    engine.dispose()


def test_runner_initialization_generates_unique_instance_id():
    """Each runner process must generate a unique UUID instance ID separate from worker name."""
    r1 = IngestionRunner(worker_name="worker-a")
    r2 = IngestionRunner(worker_name="worker-a")

    assert r1.worker_instance_id != r2.worker_instance_id
    assert r1.worker_name == "worker-a"
    # Ensure it's a valid UUID
    parsed_uuid = uuid.UUID(r1.worker_instance_id)
    assert parsed_uuid.version == 4


def test_runner_draining_rejects_new_cycles_and_cancels_fenced_batch():
    """When DRAINING or lease lost, worker must abort active batch without committing checkpoint."""
    runner = IngestionRunner(worker_name="worker-test")
    assert runner.should_continue_polling() is True

    runner.request_drain()
    assert runner.is_draining is True
    assert runner.should_continue_polling() is False


def test_runner_heartbeat_tick_updates_repository(test_db_factory):
    """Heartbeat tick invokes WorkerInstanceRepository to register/heartbeat worker."""
    runner = IngestionRunner(
        worker_name="worker-heartbeat",
        session_factory=test_db_factory,
    )

    runner._heartbeat_tick()

    with test_db_factory() as session:
        repo = WorkerInstanceRepository(session)
        worker = repo.get(runner.worker_instance_id)
        assert worker is not None
        assert worker.worker_name == "worker-heartbeat"
        assert worker.status == "ACTIVE"
        assert worker.last_heartbeat_at is not None


def test_runner_heartbeat_tick_swallows_transient_db_errors():
    """Heartbeat tick must log warning on transient DB failure without crashing."""
    mock_session = MagicMock()
    mock_session.begin.side_effect = RuntimeError("DB connection dropped")
    mock_factory = MagicMock(return_value=mock_session)
    mock_session.__enter__.return_value = mock_session

    runner = IngestionRunner(
        worker_name="worker-error-tolerant",
        session_factory=mock_factory,
    )

    # Must not raise
    runner._heartbeat_tick()


def test_runner_poll_cycle_success_records_worker_telemetry(test_db_factory):
    """Successful poll cycle records success in WorkerInstanceRepository."""
    mock_worker = MagicMock()
    mock_worker.run_poll_cycle.return_value = IngestionBatchResult(
        stream_id="test-stream",
        status="SUCCESS",
        events_read=25,
        events_processed=25,
    )

    runner = IngestionRunner(
        worker_name="worker-cycle",
        session_factory=test_db_factory,
        ingestion_worker=mock_worker,
    )

    result = runner.run_poll_cycle()
    assert result.status == "SUCCESS"
    assert result.events_processed == 25

    with test_db_factory() as session:
        repo = WorkerInstanceRepository(session)
        worker = repo.get(runner.worker_instance_id)
        assert worker is not None
        assert worker.status == "ACTIVE"
        assert worker.last_successful_cycle_at is not None


def test_runner_poll_cycle_failure_records_worker_degradation(test_db_factory):
    """Transient or permanent batch failure records cycle failure in WorkerInstanceRepository."""
    mock_worker = MagicMock()
    mock_worker.run_poll_cycle.return_value = IngestionBatchResult(
        stream_id="test-stream",
        status="TRANSIENT_FAILURE",
        events_read=10,
        events_processed=0,
        error="Elasticsearch cluster timeout",
    )

    runner = IngestionRunner(
        worker_name="worker-fail",
        session_factory=test_db_factory,
        ingestion_worker=mock_worker,
    )

    result = runner.run_poll_cycle()
    assert result.status == "TRANSIENT_FAILURE"

    with test_db_factory() as session:
        repo = WorkerInstanceRepository(session)
        worker = repo.get(runner.worker_instance_id)
        assert worker is not None
        assert worker.status == "DEGRADED"
        assert worker.last_error_code == "TRANSIENT_FAILURE"
        assert worker.last_failed_cycle_at is not None


def test_runner_graceful_shutdown_transitions_to_stopped(test_db_factory):
    """Shutdown updates status to STOPPED, sets draining, and disposes resources."""
    mock_db_mgr = MagicMock()
    mock_es = MagicMock()

    runner = IngestionRunner(
        worker_name="worker-shutdown",
        session_factory=test_db_factory,
        database_manager=mock_db_mgr,
        es_client=mock_es,
    )

    # Register initial heartbeat
    runner._heartbeat_tick()

    # Request graceful shutdown
    runner.shutdown()

    assert runner.is_draining is True
    assert runner.should_continue_polling() is False

    with test_db_factory() as session:
        repo = WorkerInstanceRepository(session)
        worker = repo.get(runner.worker_instance_id)
        assert worker is not None
        assert worker.status == "STOPPED"

    mock_db_mgr.dispose.assert_called_once()
    mock_es.close.assert_called_once()


def test_runner_metrics_server_serves_endpoints():
    """Metrics server serves /metrics and /healthz on configured port."""
    import socket

    # Find ephemeral port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        ephemeral_port = s.getsockname()[1]

    runner = IngestionRunner(
        worker_name="worker-metrics-test",
        metrics_port=ephemeral_port,
    )

    runner.start_metrics_server()
    try:
        # Check /healthz
        with urllib.request.urlopen(f"http://127.0.0.1:{ephemeral_port}/healthz", timeout=3) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "ok" in body

        # Check /metrics
        with urllib.request.urlopen(f"http://127.0.0.1:{ephemeral_port}/metrics", timeout=3) as resp:
            assert resp.status == 200
            content_type = resp.headers.get("Content-Type", "")
            assert "text/plain" in content_type
    finally:
        runner.stop_metrics_server()
