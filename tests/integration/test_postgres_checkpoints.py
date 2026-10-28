from __future__ import annotations

import concurrent.futures
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, select, text

from zylar.core.settings import get_settings
from zylar.persistence.database import DatabaseManager
from zylar.persistence.exceptions import StaleLeaseError
from zylar.persistence.models import DeadLetterEventModel, IngestionCheckpointModel
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
        pytest.fail(f"ZYLAR_REQUIRE_POSTGRES is set but PostgreSQL is unreachable: {_PG_ERROR}")


@pytest.fixture(scope="module")
def db_manager():
    settings = get_settings()
    manager = DatabaseManager(settings)
    yield manager
    manager.dispose()


@pytest.fixture
def session_factory(db_manager):
    return db_manager.session_factory


def test_postgres_checkpoint_acquire_sets_processing_status(session_factory):
    """Verifies that acquire_lease creates a new checkpoint with status PROCESSING and generation 1."""
    stream_id = f"stream-proc-{uuid.uuid4().hex[:8]}"

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        acquired, gen = uow.checkpoints.acquire_lease(
            stream_id, worker_id="worker-init", lease_seconds=60
        )
        assert acquired is True
        assert gen == 1
        uow.commit()

    # Read back directly from PostgreSQL
    session = session_factory()
    try:
        cp = session.execute(
            select(IngestionCheckpointModel).where(IngestionCheckpointModel.stream_id == stream_id)
        ).scalar_one()
        assert cp.status == "PROCESSING"
        assert cp.lease_owner == "worker-init"
        assert cp.lease_generation == 1
        assert cp.lease_expires_at is not None
    finally:
        session.close()


def test_postgres_checkpoint_concurrent_first_acquisition(session_factory):
    """Verifies that multiple concurrent threads trying to acquire an absent stream safely resolve to one winner."""
    stream_id = f"stream-race-{uuid.uuid4().hex[:8]}"
    num_workers = 5

    def attempt_acquisition(worker_idx: int) -> tuple[int, bool, int]:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            acquired, gen = uow.checkpoints.acquire_lease(
                stream_id,
                worker_id=f"worker-{worker_idx}",
                lease_seconds=60,
            )
            uow.commit()
            return worker_idx, acquired, gen

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(attempt_acquisition, i) for i in range(num_workers)]
        results = [f.result() for f in futures]

    winners = [r for r in results if r[1] is True]
    losers = [r for r in results if r[1] is False]

    assert len(winners) == 1, f"Expected exactly 1 winner, got: {results}"
    assert len(losers) == num_workers - 1
    assert winners[0][2] == 1  # Generation 1


def test_postgres_checkpoint_advance_rejects_stale_generation(session_factory):
    """Verifies that an old worker cannot advance a checkpoint after a newer lease generation has been issued."""
    stream_id = f"stream-fence-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)

    # Worker A acquires generation 1 with a 1-second lease
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        acquired_a, gen_a = uow.checkpoints.acquire_lease(
            stream_id, worker_id="worker-A", lease_seconds=1
        )
        assert acquired_a is True
        assert gen_a == 1
        uow.commit()

    # Expire Worker A's lease manually in database to simulate timeout
    session = session_factory()
    try:
        cp = session.execute(
            select(IngestionCheckpointModel).where(IngestionCheckpointModel.stream_id == stream_id)
        ).scalar_one()
        cp.lease_expires_at = now - timedelta(seconds=10)
        session.commit()
    finally:
        session.close()

    # Worker B acquires the expired lease -> gets generation 2
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        acquired_b, gen_b = uow.checkpoints.acquire_lease(
            stream_id, worker_id="worker-B", lease_seconds=60
        )
        assert acquired_b is True
        assert gen_b == 2
        uow.commit()

    # Worker A now attempts to commit/advance using stale generation 1 -> must raise StaleLeaseError
    with pytest.raises(StaleLeaseError) as exc_info:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            uow.checkpoints.advance_checkpoint(
                stream_id=stream_id,
                new_timestamp=now + timedelta(minutes=5),
                last_id="evt-stale",
                processed_count=10,
                worker_id="worker-A",
                lease_generation=1,  # Stale!
            )
            uow.commit()

    assert "Stale lease" in str(exc_info.value)

    # Confirm database watermark remains untouched
    session = session_factory()
    try:
        cp_check = session.execute(
            select(IngestionCheckpointModel).where(IngestionCheckpointModel.stream_id == stream_id)
        ).scalar_one()
        assert cp_check.lease_owner == "worker-B"
        assert cp_check.lease_generation == 2
        assert cp_check.last_processed_id != "evt-stale"
    finally:
        session.close()


def test_postgres_checkpoint_retry_gating(session_factory):
    """Verifies that record_failure schedules exponential backoff and acquire_lease rejects attempts before next_retry_at."""
    stream_id = f"stream-retry-{uuid.uuid4().hex[:8]}"

    # Initial acquisition
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        acquired, gen = uow.checkpoints.acquire_lease(
            stream_id, worker_id="worker-temp", lease_seconds=60
        )
        assert acquired is True
        assert gen == 1
        uow.commit()

    # Failure with 30s backoff (passing worker_id and lease_generation)
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        failed_cp = uow.checkpoints.record_failure(
            stream_id=stream_id,
            error="Connection timeout to Elasticsearch",
            worker_id="worker-temp",
            lease_generation=1,
            max_retries=3,
            backoff_initial_seconds=30.0,
            jitter_fn=lambda d: d,
        )
        assert failed_cp.status == "RETRYING"
        assert failed_cp.lease_owner is None
        assert failed_cp.next_retry_at is not None
        uow.commit()

    # Attempt acquisition immediately -> must be rejected because next_retry_at is in the future
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        acquired, gen = uow.checkpoints.acquire_lease(
            stream_id, worker_id="worker-eager", lease_seconds=60
        )
        assert acquired is False
        uow.commit()


def test_postgres_checkpoint_record_failure_stale_worker_race(session_factory):
    """Verifies that a stale worker cannot record a failure against a newer lease generation."""
    stream_id = f"stream-fail-race-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)

    # Worker A acquires generation 1
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        uow.checkpoints.acquire_lease(stream_id, worker_id="worker-A", lease_seconds=1)
        uow.commit()

    # Manually expire Worker A's lease to simulate timeout
    session = session_factory()
    try:
        cp = session.execute(
            select(IngestionCheckpointModel).where(IngestionCheckpointModel.stream_id == stream_id)
        ).scalar_one()
        cp.lease_expires_at = now - timedelta(seconds=5)
        session.commit()
    finally:
        session.close()

    # Worker B acquires generation 2
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        acquired_b, gen_b = uow.checkpoints.acquire_lease(
            stream_id, worker_id="worker-B", lease_seconds=60
        )
        assert acquired_b is True
        assert gen_b == 2
        uow.commit()

    # Stale Worker A now attempts to record failure with generation 1 -> must raise StaleLeaseError
    with pytest.raises(StaleLeaseError) as exc_info:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            uow.checkpoints.record_failure(
                stream_id=stream_id,
                error="Stale worker timeout",
                worker_id="worker-A",
                lease_generation=1,
            )
            uow.commit()

    assert "Stale lease failure report" in str(exc_info.value)

    # Confirm Worker B's active lease in PostgreSQL is completely untouched
    session = session_factory()
    try:
        cp_check = session.execute(
            select(IngestionCheckpointModel).where(IngestionCheckpointModel.stream_id == stream_id)
        ).scalar_one()
        assert cp_check.lease_owner == "worker-B"
        assert cp_check.lease_generation == 2
        assert cp_check.status == "PROCESSING"
        assert cp_check.retry_count == 0
    finally:
        session.close()


def test_postgres_checkpoint_release_with_stale_generation_rejected(session_factory):
    """Verifies that releasing with a stale generation returns False and leaves the active lease intact."""
    stream_id = f"stream-rel-fence-{uuid.uuid4().hex[:8]}"

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        uow.checkpoints.acquire_lease(stream_id, worker_id="worker-active", lease_seconds=60)
        uow.commit()

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        # Attempt to release with stale generation 0
        released = uow.checkpoints.release_lease(
            stream_id, worker_id="worker-active", lease_generation=0
        )
        assert released is False
        uow.commit()

    # Verify active lease remains held
    session = session_factory()
    try:
        cp = session.execute(
            select(IngestionCheckpointModel).where(IngestionCheckpointModel.stream_id == stream_id)
        ).scalar_one()
        assert cp.lease_owner == "worker-active"
        assert cp.status == "PROCESSING"
    finally:
        session.close()


def test_postgres_dead_letter_deduplication_and_null_event_id(session_factory):
    """Verifies that duplicate non-null event_id records are ignored, while null event_id records are preserved."""
    stream_id = f"stream-dlq-{uuid.uuid4().hex[:8]}"

    items: list[dict[str, Any]] = [
        {
            "event_id": "evt-dup-1",
            "raw_payload": {"message": "invalid schema"},
            "error_reason": "INVALID_SCHEMA",
        },
        {
            "event_id": "evt-dup-1",  # Duplicate in same batch
            "raw_payload": {"message": "invalid schema"},
            "error_reason": "INVALID_SCHEMA",
        },
        {
            "event_id": None,  # Null event_id 1
            "raw_payload": {"unparseable": True},
            "error_reason": "UNPARSEABLE",
        },
        {
            "event_id": None,  # Null event_id 2
            "raw_payload": {"unparseable": True},
            "error_reason": "UNPARSEABLE",
        },
    ]

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        count1 = uow.checkpoints.quarantine_events(stream_id, items)
        assert count1 == 3  # 1 for evt-dup-1 + 2 for the two null event_ids
        uow.commit()

    # Re-insert the duplicate event_id again in a separate transaction
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        count2 = uow.checkpoints.quarantine_events(
            stream_id,
            [
                {
                    "event_id": "evt-dup-1",
                    "raw_payload": {"message": "invalid schema"},
                    "error_reason": "INVALID_SCHEMA",
                }
            ],
        )
        assert count2 == 0  # Deduplicated!
        uow.commit()

    # Check total rows in database
    session = session_factory()
    try:
        rows = (
            session.execute(
                select(DeadLetterEventModel).where(DeadLetterEventModel.stream_id == stream_id)
            )
            .scalars()
            .all()
        )
        assert len(rows) == 3
        event_ids = [r.event_id for r in rows]
        assert event_ids.count("evt-dup-1") == 1
        assert event_ids.count(None) == 2
    finally:
        session.close()


def test_postgres_dead_letter_oversized_payload_rejected(session_factory):
    """Verifies that payloads exceeding 64 KiB are rejected before database insertion."""
    stream_id = f"stream-dlq-large-{uuid.uuid4().hex[:8]}"
    large_payload = {"blob": "Z" * 70000}
    large_items: list[dict[str, Any]] = [{"event_id": "large-evt", "raw_payload": large_payload}]

    with pytest.raises(ValueError) as exc_info:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            uow.checkpoints.quarantine_events(
                stream_id,
                large_items,
            )

    assert "exceeds 64 KiB limit" in str(exc_info.value)
