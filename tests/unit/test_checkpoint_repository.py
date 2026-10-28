from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from zylar.persistence.exceptions import RecordNotFoundError
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
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()
    mock_session.commit.assert_not_called()


def test_checkpoint_acquire_lease_new_stream():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec

    granted = repo.acquire_lease("stream-auth", worker_id="worker-alpha", lease_seconds=60)
    assert granted is True
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
        lease_expires_at=now + timedelta(seconds=120),
        status="RUNNING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = existing
    mock_session.execute.return_value = mock_exec

    granted = repo.acquire_lease("stream-auth", worker_id="worker-me", lease_seconds=60)
    assert granted is False
    mock_session.commit.assert_not_called()


def test_checkpoint_acquire_lease_expired_or_owner_accepted():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    # Expired lease
    expired = IngestionCheckpointModel(
        stream_id="stream-auth",
        last_processed_timestamp=now - timedelta(hours=1),
        lease_owner="worker-dead",
        lease_expires_at=now - timedelta(seconds=30),
        status="RUNNING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = expired
    mock_session.execute.return_value = mock_exec

    granted = repo.acquire_lease("stream-auth", worker_id="worker-new", lease_seconds=60)
    assert granted is True
    assert expired.lease_owner == "worker-new"
    assert expired.status == "RUNNING"
    mock_session.flush.assert_called_once()


def test_checkpoint_release_lease():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    owned = IngestionCheckpointModel(
        stream_id="stream-release",
        last_processed_timestamp=now,
        lease_owner="worker-owner",
        lease_expires_at=now + timedelta(seconds=60),
        status="RUNNING",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = owned
    mock_session.execute.return_value = mock_exec

    # Releasing as owner resets lease
    repo.release_lease("stream-release", worker_id="worker-owner")
    assert owned.lease_owner is None
    assert owned.lease_expires_at is None
    assert owned.status == "IDLE"
    mock_session.flush.assert_called_once()


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
        status="RUNNING",
        lease_owner="worker-1",
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
    )

    assert advanced.last_processed_timestamp == new_time
    assert advanced.last_processed_id == "doc-15"
    assert advanced.batch_sequence == 4
    assert advanced.events_processed_count == 105
    assert advanced.retry_count == 0
    assert advanced.last_error is None
    mock_session.flush.assert_called_once()


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
        )


def test_checkpoint_record_failure_retrying_and_failed():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    now = datetime.now(UTC)
    cp = IngestionCheckpointModel(
        stream_id="stream-fail",
        last_processed_timestamp=now,
        retry_count=0,
        status="RUNNING",
        lease_owner="worker-1",
    )
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = cp
    mock_session.execute.return_value = mock_exec

    # First failure -> RETRYING
    res1 = repo.record_failure("stream-fail", error="ES timeout", max_retries=2, backoff_seconds=10)
    assert res1.retry_count == 1
    assert res1.status == "RETRYING"
    assert res1.lease_owner is None
    assert res1.last_error == "ES timeout"

    # Second failure -> FAILED (reaches max_retries)
    res2 = repo.record_failure("stream-fail", error="ES connection refused", max_retries=2, backoff_seconds=10)
    assert res2.retry_count == 2
    assert res2.status == "FAILED"


def test_checkpoint_quarantine_events():
    mock_session = MagicMock(spec=Session)
    repo = CheckpointRepository(mock_session)

    items = [
        {
            "event_id": "bad-1",
            "raw_payload": {"msg": "bad event"},
            "error_reason": "MALFORMED_JSON",
            "error_details": "Syntax error at col 4",
        }
    ]

    quarantined = repo.quarantine_events("stream-bad", items)
    assert len(quarantined) == 1
    assert quarantined[0].event_id == "bad-1"
    assert quarantined[0].error_reason == "MALFORMED_JSON"
    assert len(quarantined[0].raw_event_hash) == 64
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()


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
