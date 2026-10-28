from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from zylar.persistence.exceptions import RecordNotFoundError, StaleLeaseError
from zylar.persistence.models import IngestionCheckpointModel
from zylar.persistence.repositories import CheckpointRepository


def test_checkpoint_does_not_commit_or_close_session():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    repo.get("stream-test")
    mock_session.commit.assert_not_called()
    mock_session.close.assert_not_called()


def test_checkpoint_get_or_create_existing():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    existing = IngestionCheckpointModel(
        stream_id="stream-1",
        last_processed_timestamp=datetime(2026, 10, 28, 10, 0, tzinfo=UTC),
        lease_generation=1,
        status="IDLE",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = existing
    mock_session.execute.return_value = mock_exec

    result = repo.get_or_create("stream-1", default_start_time=datetime.now(UTC))
    assert result is existing
    mock_session.add.assert_not_called()
    mock_session.commit.assert_not_called()


def test_checkpoint_get_or_create_new():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec

    start_time = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
    result = repo.get_or_create("stream-new", default_start_time=start_time)

    assert result.stream_id == "stream-new"
    assert result.last_processed_timestamp == start_time
    assert result.status == "IDLE"
    assert result.lease_generation == 0
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()
    mock_session.commit.assert_not_called()


def test_checkpoint_acquire_lease_new_stream():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec

    granted, generation = repo.acquire_lease(
        "stream-auth", worker_id="worker-alpha", lease_seconds=60
    )
    assert granted is True
    assert generation == 1
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()
    mock_session.commit.assert_not_called()


def test_checkpoint_acquire_lease_unexpired_other_worker_rejected():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    existing = IngestionCheckpointModel(
        stream_id="stream-auth",
        last_processed_timestamp=now,
        lease_owner="worker-other",
        lease_generation=3,
        lease_expires_at=now + timedelta(seconds=120),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = existing
    mock_session.execute.return_value = mock_exec

    granted, generation = repo.acquire_lease("stream-auth", worker_id="worker-me", lease_seconds=60)
    assert granted is False
    assert generation == 3
    mock_session.commit.assert_not_called()


def test_checkpoint_acquire_lease_unexpired_other_worker_rejected_even_if_idle_or_failed():
    """Invariant 2: An unexpired lease belonging to another worker cannot be stolen just because status is IDLE/FAILED."""
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    idle_checkpoint = IngestionCheckpointModel(
        stream_id="stream-invariant-2",
        last_processed_timestamp=now,
        lease_owner="worker-current",
        lease_generation=5,
        lease_expires_at=now + timedelta(seconds=90),
        status="IDLE",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = idle_checkpoint
    mock_session.execute.return_value = mock_exec

    granted, gen = repo.acquire_lease(
        "stream-invariant-2", worker_id="worker-attacker", lease_seconds=60
    )
    assert granted is False
    assert gen == 5
    assert idle_checkpoint.lease_owner == "worker-current"


def test_checkpoint_acquire_lease_missing_expiry_not_stealable():
    """Invariant 3: A missing lease expiry must not automatically authorize stealing a lease that still has an owner."""
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    no_expiry_checkpoint = IngestionCheckpointModel(
        stream_id="stream-invariant-3",
        last_processed_timestamp=now,
        lease_owner="worker-holding",
        lease_generation=2,
        lease_expires_at=None,
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = no_expiry_checkpoint
    mock_session.execute.return_value = mock_exec

    granted, gen = repo.acquire_lease(
        "stream-invariant-3", worker_id="worker-other", lease_seconds=60
    )
    assert granted is False
    assert gen == 2


def test_checkpoint_acquire_lease_rejected_when_retrying_before_next_retry_at():
    """Enforces retry cooldown: acquisition must be rejected before next_retry_at even if lease is unowned."""
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cooldown_cp = IngestionCheckpointModel(
        stream_id="stream-cooldown",
        last_processed_timestamp=now - timedelta(minutes=5),
        lease_owner=None,
        lease_expires_at=None,
        lease_generation=4,
        retry_count=2,
        next_retry_at=now + timedelta(seconds=45),
        status="RETRYING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cooldown_cp
    mock_session.execute.return_value = mock_exec

    granted, gen = repo.acquire_lease("stream-cooldown", worker_id="worker-ready", lease_seconds=60)
    assert granted is False
    assert gen == 4


def test_checkpoint_acquire_lease_expired_or_owner_accepted():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    expired = IngestionCheckpointModel(
        stream_id="stream-auth",
        last_processed_timestamp=now - timedelta(hours=1),
        lease_owner="worker-dead",
        lease_generation=7,
        lease_expires_at=now - timedelta(seconds=30),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = expired
    mock_session.execute.return_value = mock_exec

    granted, generation = repo.acquire_lease(
        "stream-auth", worker_id="worker-new", lease_seconds=60
    )
    assert granted is True
    assert generation == 8
    assert expired.lease_owner == "worker-new"
    assert expired.lease_generation == 8
    assert expired.status == "PROCESSING"
    mock_session.flush.assert_called_once()


def test_checkpoint_reacquire_after_expiry_increments_lease_generation():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    expired = IngestionCheckpointModel(
        stream_id="stream-gen",
        last_processed_timestamp=now,
        lease_owner="worker-old",
        lease_generation=10,
        lease_expires_at=now - timedelta(seconds=5),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = expired
    mock_session.execute.return_value = mock_exec

    granted, gen = repo.acquire_lease("stream-gen", worker_id="worker-revived", lease_seconds=60)
    assert granted is True
    assert gen == 11
    assert expired.lease_generation == 11
    assert expired.lease_owner == "worker-revived"


def test_checkpoint_release_lease():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    owned = IngestionCheckpointModel(
        stream_id="stream-release",
        last_processed_timestamp=now,
        lease_owner="worker-owner",
        lease_generation=2,
        lease_expires_at=now + timedelta(seconds=60),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = owned
    mock_session.execute.return_value = mock_exec

    released = repo.release_lease("stream-release", worker_id="worker-owner", lease_generation=2)
    assert released is True
    assert owned.lease_owner is None
    assert owned.lease_expires_at is None
    assert owned.status == "IDLE"
    mock_session.flush.assert_called_once()


def test_checkpoint_release_lease_rejects_stale_generation_and_preserves_owner():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    owned = IngestionCheckpointModel(
        stream_id="stream-release-stale",
        last_processed_timestamp=now,
        lease_owner="worker-new-owner",
        lease_generation=3,
        lease_expires_at=now + timedelta(seconds=60),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = owned
    mock_session.execute.return_value = mock_exec

    # Stale worker attempts to release with old generation 2
    released = repo.release_lease(
        "stream-release-stale", worker_id="worker-new-owner", lease_generation=2
    )
    assert released is False
    assert owned.lease_owner == "worker-new-owner"
    assert owned.lease_generation == 3


def test_checkpoint_renew_lease():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    owned = IngestionCheckpointModel(
        stream_id="stream-renew",
        last_processed_timestamp=now,
        lease_owner="worker-owner",
        lease_generation=4,
        lease_expires_at=now + timedelta(seconds=20),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = owned
    mock_session.execute.return_value = mock_exec

    # Matching generation extends lease
    renewed = repo.renew_lease(
        "stream-renew", worker_id="worker-owner", lease_generation=4, lease_seconds=60
    )
    assert renewed is True
    assert owned.lease_expires_at is not None
    assert owned.lease_expires_at > now + timedelta(seconds=50)

    # Mismatched generation rejected
    renewed_stale = repo.renew_lease("stream-renew", worker_id="worker-owner", lease_generation=3)
    assert renewed_stale is False


def test_checkpoint_advance_watermark_success():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-advance",
        last_processed_timestamp=now - timedelta(minutes=10),
        last_processed_id="doc-10",
        batch_sequence=3,
        events_processed_count=100,
        retry_count=2,
        last_error="previous error",
        status="PROCESSING",
        lease_owner="worker-1",
        lease_generation=5,
        lease_expires_at=now + timedelta(seconds=60),
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    new_time = now - timedelta(minutes=5)
    advanced = repo.advance_checkpoint(
        stream_id="stream-advance",
        new_timestamp=new_time,
        last_id="doc-15",
        processed_count=5,
        worker_id="worker-1",
        lease_generation=5,
    )

    assert advanced.last_processed_timestamp == new_time
    assert advanced.last_processed_id == "doc-15"
    assert advanced.batch_sequence == 4
    assert advanced.events_processed_count == 105
    assert advanced.retry_count == 0
    assert advanced.next_retry_at is None
    assert advanced.last_error is None
    assert advanced.status == "PROCESSING"
    mock_session.flush.assert_called_once()


def test_checkpoint_advance_rejects_stale_lease_generation():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-advance-fenced",
        last_processed_timestamp=now,
        lease_owner="worker-1",
        lease_generation=6,
        lease_expires_at=now + timedelta(seconds=60),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    with pytest.raises(StaleLeaseError) as exc_info:
        repo.advance_checkpoint(
            stream_id="stream-advance-fenced",
            new_timestamp=now + timedelta(seconds=10),
            worker_id="worker-1",
            lease_generation=5,  # Stale generation!
        )
    assert "Stale lease" in str(exc_info.value)
    assert "generation 6" in str(exc_info.value)


def test_checkpoint_advance_rejects_mismatched_worker():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-advance-worker",
        last_processed_timestamp=now,
        lease_owner="worker-owner",
        lease_generation=1,
        lease_expires_at=now + timedelta(seconds=60),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    with pytest.raises(StaleLeaseError) as exc_info:
        repo.advance_checkpoint(
            stream_id="stream-advance-worker",
            new_timestamp=now + timedelta(seconds=10),
            worker_id="worker-imposter",
            lease_generation=1,
        )
    assert "Stale lease" in str(exc_info.value)


def test_checkpoint_advance_rejects_missing_fencing_tokens():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-missing-token",
        last_processed_timestamp=now,
        lease_owner="worker-1",
        lease_generation=1,
        lease_expires_at=now + timedelta(seconds=60),
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    with pytest.raises(StaleLeaseError) as exc_info:
        repo.advance_checkpoint(
            stream_id="stream-missing-token",
            new_timestamp=now,
            worker_id=None,
            lease_generation=None,
        )
    assert "required fencing tokens" in str(exc_info.value)


def test_checkpoint_advance_missing_raises_not_found():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec

    with pytest.raises(RecordNotFoundError):
        repo.advance_checkpoint(
            stream_id="nonexistent",
            new_timestamp=datetime.now(UTC),
            worker_id="worker-1",
            lease_generation=1,
        )


def test_checkpoint_record_failure_exponential_backoff_and_jitter():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    ref_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-fail-backoff",
        last_processed_timestamp=ref_time,
        retry_count=0,
        lease_generation=2,
        status="PROCESSING",
        lease_owner="worker-1",
        lease_expires_at=ref_time + timedelta(seconds=60),
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    # Failure 1: base_delay = 2.0 * (2^0) = 2.0s
    res1 = repo.record_failure(
        "stream-fail-backoff",
        error="ES timeout",
        worker_id="worker-1",
        lease_generation=2,
        max_retries=4,
        backoff_initial_seconds=2.0,
        backoff_factor=2.0,
        backoff_max_seconds=30.0,
        jitter_fn=lambda d: d,  # deterministic jitter
        now=ref_time,
    )
    assert res1.retry_count == 1
    assert res1.status == "RETRYING"
    assert res1.lease_owner is None
    assert res1.lease_expires_at is None
    assert res1.next_retry_at == ref_time + timedelta(seconds=2.0)

    # Re-arm lease for worker-1 with generation 2 to simulate continuous failure attempts in same lease
    cp.lease_owner = "worker-1"
    cp.lease_expires_at = ref_time + timedelta(seconds=60)

    # Failure 2: base_delay = 2.0 * (2^1) = 4.0s
    res2 = repo.record_failure(
        "stream-fail-backoff",
        error="ES timeout 2",
        worker_id="worker-1",
        lease_generation=2,
        max_retries=4,
        backoff_initial_seconds=2.0,
        backoff_factor=2.0,
        backoff_max_seconds=30.0,
        jitter_fn=lambda d: d,
        now=ref_time,
    )
    assert res2.retry_count == 2
    assert res2.status == "RETRYING"
    assert res2.next_retry_at == ref_time + timedelta(seconds=4.0)

    cp.lease_owner = "worker-1"
    cp.lease_expires_at = ref_time + timedelta(seconds=60)

    # Failure 3: base_delay = 2.0 * (2^2) = 8.0s
    res3 = repo.record_failure(
        "stream-fail-backoff",
        error="ES timeout 3",
        worker_id="worker-1",
        lease_generation=2,
        max_retries=4,
        backoff_initial_seconds=2.0,
        backoff_factor=2.0,
        backoff_max_seconds=30.0,
        jitter_fn=lambda d: d,
        now=ref_time,
    )
    assert res3.retry_count == 3
    assert res3.status == "RETRYING"
    assert res3.next_retry_at == ref_time + timedelta(seconds=8.0)

    cp.lease_owner = "worker-1"
    cp.lease_expires_at = ref_time + timedelta(seconds=60)

    # Failure 4: reaches max_retries=4 -> FAILED, next_retry_at is None
    res4 = repo.record_failure(
        "stream-fail-backoff",
        error="Fatal outage",
        worker_id="worker-1",
        lease_generation=2,
        max_retries=4,
        backoff_initial_seconds=2.0,
        backoff_factor=2.0,
        backoff_max_seconds=30.0,
        jitter_fn=lambda d: d,
        now=ref_time,
    )
    assert res4.retry_count == 4
    assert res4.status == "FAILED"
    assert res4.next_retry_at is None
    assert res4.lease_owner is None


def test_checkpoint_record_failure_rejects_stale_generation():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-fail-stale",
        last_processed_timestamp=now,
        retry_count=0,
        lease_generation=5,
        status="PROCESSING",
        lease_owner="worker-active",
        lease_expires_at=now + timedelta(seconds=60),
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    # Worker with stale generation 4 attempts to report failure
    with pytest.raises(StaleLeaseError) as exc_info:
        repo.record_failure(
            "stream-fail-stale",
            error="Old failure",
            worker_id="worker-active",
            lease_generation=4,
        )
    assert "Stale lease failure report" in str(exc_info.value)
    assert cp.retry_count == 0  # untouched!


def test_checkpoint_record_failure_rejects_expired_lease():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-fail-expired",
        last_processed_timestamp=now,
        retry_count=0,
        lease_generation=2,
        status="PROCESSING",
        lease_owner="worker-expired",
        lease_expires_at=now - timedelta(seconds=10),
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    with pytest.raises(StaleLeaseError) as exc_info:
        repo.record_failure(
            "stream-fail-expired",
            error="Expired worker failure",
            worker_id="worker-expired",
            lease_generation=2,
            now=now,
        )
    assert "lease is missing or expired" in str(exc_info.value)


def test_checkpoint_advance_rejects_missing_lease_expiry():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-advance-no-expiry",
        last_processed_timestamp=now,
        lease_owner="worker-1",
        lease_generation=1,
        lease_expires_at=None,
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    with pytest.raises(StaleLeaseError) as exc_info:
        repo.advance_checkpoint(
            stream_id="stream-advance-no-expiry",
            new_timestamp=now,
            worker_id="worker-1",
            lease_generation=1,
        )
    assert "lease is missing or expired" in str(exc_info.value)


def test_checkpoint_renew_rejects_missing_lease_expiry():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-renew-no-expiry",
        last_processed_timestamp=now,
        lease_owner="worker-1",
        lease_generation=1,
        lease_expires_at=None,
        status="PROCESSING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    renewed = repo.renew_lease("stream-renew-no-expiry", worker_id="worker-1", lease_generation=1)
    assert renewed is False


def test_checkpoint_quarantine_events_success_and_deduplication():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    items = [
        {
            "event_id": "bad-1",
            "raw_payload": {"msg": "bad event"},
            "error_reason": "MALFORMED_JSON",
            "error_details": "Syntax error at col 4",
        },
        {
            "event_id": "bad-2",
            "raw_payload": {"msg": "bad event 2"},
            "error_reason": "MALFORMED_JSON",
        },
    ]

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec

    inserted_count = repo.quarantine_events("stream-bad", items)
    assert inserted_count == 2
    assert mock_session.add.call_count == 2
    mock_session.flush.assert_called_once()


def test_checkpoint_quarantine_oversized_payload_rejected():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    # 65 KiB payload (> 64 KiB limit)
    oversized_data = {"data": "X" * 66000}
    items = [
        {
            "event_id": "oversized-event",
            "raw_payload": oversized_data,
            "error_reason": "PAYLOAD_TOO_LARGE",
        }
    ]

    with pytest.raises(ValueError) as exc_info:
        repo.quarantine_events("stream-oversized", items)
    assert "exceeds 64 KiB limit" in str(exc_info.value)
    mock_session.add.assert_not_called()


def test_checkpoint_lag_seconds():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    ten_min_ago = now - timedelta(minutes=10)
    cp = IngestionCheckpointModel(
        stream_id="stream-lag",
        last_processed_timestamp=ten_min_ago,
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    lag = repo.get_checkpoint_lag_seconds("stream-lag")
    assert lag is not None
    assert 590 <= lag <= 610
