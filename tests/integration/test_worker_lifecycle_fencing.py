from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from api.main import app
from fastapi.testclient import TestClient
from sqlalchemy import text

from zylar.core.security import Role, create_access_token
from zylar.core.settings import get_settings
from zylar.ingestion.runner import IngestionRunner
from zylar.persistence.database import DatabaseManager
from zylar.persistence.dtos import IncidentCreate
from zylar.persistence.exceptions import FencedLeaseError, StaleLeaseError
from zylar.persistence.models import IngestionCheckpointModel
from zylar.persistence.repositories import CheckpointRepository, WorkerInstanceRepository
from zylar.persistence.unit_of_work import UnitOfWork


@pytest.fixture
def db_manager():
    settings = get_settings()
    manager = DatabaseManager(settings)
    manager.check_connection()
    yield manager
    manager.dispose()


def test_worker_lifecycle_heartbeat_and_graceful_shutdown(db_manager: DatabaseManager):
    """Verifies worker registration, periodic heartbeats, and graceful shutdown to STOPPED."""
    session_factory = db_manager.session_factory
    worker_name = f"worker-test-{uuid.uuid4().hex[:6]}"

    runner = IngestionRunner(
        worker_name=worker_name,
        session_factory=session_factory,
    )

    # Initial heartbeat tick
    runner._heartbeat_tick()

    with session_factory() as session:
        repo = WorkerInstanceRepository(session)
        worker = repo.get(runner.worker_instance_id)
        assert worker is not None
        assert worker.worker_name == worker_name
        assert worker.status == "ACTIVE"
        assert worker.last_heartbeat_at is not None

        # Verify query for active workers returns our runner
        active_workers = repo.get_active_workers(worker_name=worker_name)
        assert any(w.worker_instance_id == runner.worker_instance_id for w in active_workers)

    # Graceful shutdown
    runner.shutdown()

    with session_factory() as session:
        repo = WorkerInstanceRepository(session)
        worker = repo.get(runner.worker_instance_id)
        assert worker is not None
        assert worker.status == "STOPPED"

        # Stopped worker must not appear in active workers query
        active_workers = repo.get_active_workers(worker_name=worker_name)
        assert not any(w.worker_instance_id == runner.worker_instance_id for w in active_workers)


def test_lease_fencing_prevents_stale_commit_and_rolls_back(db_manager: DatabaseManager):
    """When a worker's lease is superseded by a newer generation, advancing watermark raises FencedLeaseError and rolls back."""
    session_factory = db_manager.session_factory
    stream_id = f"fencing-stream-{uuid.uuid4().hex[:8]}"
    worker_a = f"worker-a-{uuid.uuid4().hex[:6]}"
    worker_b = f"worker-b-{uuid.uuid4().hex[:6]}"

    now = datetime.now(UTC)

    # 1. Initialize checkpoint and lease to Worker A (generation 1)
    with session_factory() as session:
        with session.begin():
            repo = CheckpointRepository(session)
            acquired_a, gen_a = repo.acquire_lease(
                stream_id=stream_id,
                worker_id=worker_a,
                lease_seconds=30,
            )
            assert acquired_a is True
            assert gen_a == 1

    # 2. Worker B steals the lease after simulated expiry (bumping generation to 2)
    with session_factory() as session:
        with session.begin():
            cp = session.query(IngestionCheckpointModel).filter_by(stream_id=stream_id).one()
            # Force expiry to simulate time passage
            cp.lease_expires_at = now - timedelta(seconds=10)
            session.flush()

            repo = CheckpointRepository(session)
            acquired_b, gen_b = repo.acquire_lease(
                stream_id=stream_id,
                worker_id=worker_b,
                lease_seconds=60,
            )
            assert acquired_b is True
            assert gen_b == 2

    # 3. Worker A finishes its slow batch and attempts to advance watermark with generation 1
    # Single atomic transaction should attempt to persist incident and advance checkpoint
    with pytest.raises(FencedLeaseError) as exc_info:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            # Attempt to commit incident
            uow.persist_incident_lifecycle(
                IncidentCreate(
                    incident_id="fenced-incident-1",
                    idempotency_key="idemp-fenced-1",
                    timestamp=now,
                    attack_classification="BRUTE_FORCE",
                    risk_score=75,
                    risk_category="HIGH",
                    mitigation_plan=["Block source IP"],
                )
            )
            # Attempt to advance watermark with stale generation 1
            uow.checkpoints.advance_checkpoint(
                stream_id=stream_id,
                new_timestamp=now + timedelta(minutes=5),
                last_id="fenced-event-999",
                processed_count=100,
                worker_id=worker_a,
                lease_generation=gen_a,  # 1 is stale!
                lease_seconds=30,
            )
            uow.commit()

    assert "Stale lease for stream" in str(exc_info.value)
    assert issubclass(FencedLeaseError, StaleLeaseError)

    # 4. Verify rollback: incident was NOT persisted, and checkpoint remains at generation 2 under Worker B
    with session_factory() as session:
        # Check incident was rolled back
        incident = session.execute(
            text("SELECT id FROM incidents WHERE incident_id = 'fenced-incident-1'")
        ).scalar_one_or_none()
        assert incident is None

        # Check checkpoint still owned by Worker B with generation 2
        repo = CheckpointRepository(session)
        cp = repo.get(stream_id)
        assert cp is not None
        assert cp.lease_owner == worker_b
        assert cp.lease_generation == 2
        assert cp.events_processed_count == 0


def test_api_ingestion_status_reports_worker_liveness(db_manager: DatabaseManager):
    """API /api/ingestion/status reports active worker instances, heartbeat lag, and lease ownership."""
    session_factory = db_manager.session_factory
    worker_id = str(uuid.uuid4())
    worker_name = f"worker-status-test-{uuid.uuid4().hex[:6]}"

    # Register an active worker
    with session_factory() as session:
        with session.begin():
            repo = WorkerInstanceRepository(session)
            repo.register_or_heartbeat(
                worker_instance_id=worker_id,
                worker_name=worker_name,
                status="ACTIVE",
            )

    token = create_access_token(subject="admin", role=Role.ADMIN)

    with TestClient(app) as client:
        resp = client.get(
            "/api/ingestion/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()

        assert "active_workers" in data
        assert "workers_count" in data
        assert data["workers_count"] >= 1

        active = [w for w in data["active_workers"] if w["worker_instance_id"] == worker_id]
        assert len(active) == 1
        assert active[0]["worker_name"] == worker_name
        assert active[0]["status"] == "ACTIVE"
        assert active[0]["heartbeat_lag_seconds"] is not None
        assert active[0]["heartbeat_lag_seconds"] < 10.0
