from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from elasticsearch.exceptions import ConnectionError as ESConnectionError

from zylar.ingestion.engine import CheckpointedIngestionWorker
from zylar.persistence.models import IngestionCheckpointModel


@pytest.fixture
def mock_uow_ctx():
    """Mocks UnitOfWork context manager and checkpoint repository."""
    with patch("zylar.ingestion.engine.UnitOfWork") as mock_uow_cls:
        mock_uow = MagicMock()
        mock_uow_cls.return_value.__enter__.return_value = mock_uow
        yield mock_uow


def test_worker_lease_not_acquired(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = False
    mock_es = MagicMock()

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "LEASE_NOT_ACQUIRED"
    assert result.events_read == 0
    mock_es.search.assert_not_called()


def test_worker_idle_no_hits(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = True
    now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=now,
        last_processed_id="doc-100",
    )

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": []}}

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "IDLE"
    assert result.events_read == 0
    mock_uow_ctx.checkpoints.release_lease.assert_called_once_with("test-stream", "test-worker")
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_not_called()


def test_worker_tie_breaker_skips_processed_events(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = True
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id="doc-002",
    )

    mock_es = MagicMock()
    # Returns 3 docs: doc-001 (older timestamp), doc-002 (equal timestamp, equal ID), doc-003 (equal timestamp, higher ID)
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-001",
                    "_source": {"timestamp": (watermark_time - timedelta(seconds=1)).isoformat()},
                },
                {
                    "_id": "doc-002",
                    "_source": {"timestamp": watermark_time.isoformat()},
                },
                {
                    "_id": "doc-003",
                    "_source": {
                        "timestamp": watermark_time.isoformat(),
                        "event_type": "ssh_login",
                        "source_ip": "10.0.0.1",
                    },
                },
            ]
        }
    }

    mock_invoker = MagicMock(return_value={"incident_id": "INC-123"})
    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
        workflow_invoker=mock_invoker,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "SUCCESS"
    assert result.events_read == 3
    assert result.events_processed == 1
    assert result.checkpoint_id == "doc-003"
    assert result.checkpoint_timestamp == watermark_time

    mock_uow_ctx.checkpoints.advance_checkpoint.assert_called_once_with(
        stream_id="test-stream",
        new_timestamp=watermark_time,
        last_id="doc-003",
        processed_count=1,
        worker_id="test-worker",
    )


def test_worker_quarantines_poison_events(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = True
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id=None,
    )

    valid_time = watermark_time + timedelta(seconds=10)
    mock_es = MagicMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-poison-1",
                    "_source": {"timestamp": "NOT_A_VALID_ISO_TIMESTAMP"},
                },
                {
                    "_id": "doc-valid-1",
                    "_source": {
                        "timestamp": valid_time.isoformat(),
                        "source": "suricata",
                        "source_ip": "192.168.1.100",
                    },
                },
            ]
        }
    }

    mock_invoker = MagicMock(return_value={})
    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
        workflow_invoker=mock_invoker,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "SUCCESS"
    assert result.events_read == 2
    assert result.events_processed == 1
    assert result.dead_letters_count == 1
    assert result.checkpoint_id == "doc-valid-1"

    # Dead letters quarantined
    mock_uow_ctx.checkpoints.quarantine_events.assert_called_once()
    # Checkpoint advanced
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_called_once_with(
        stream_id="test-stream",
        new_timestamp=valid_time,
        last_id="doc-valid-1",
        processed_count=1,
        worker_id="test-worker",
    )


def test_worker_transient_es_error_records_failure(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = True
    now = datetime.now(UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=now,
    )

    mock_es = MagicMock()
    mock_es.search.side_effect = ESConnectionError("Connection to ES timed out")

    mock_uow_ctx.checkpoints.record_failure.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=now,
        retry_count=1,
        status="RETRYING",
    )

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "TRANSIENT_FAILURE"
    assert result.retry_count == 1
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_not_called()


def test_worker_workflow_exception_does_not_advance_checkpoint(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = True
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
    )

    mock_es = MagicMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-crash",
                    "_source": {
                        "timestamp": (watermark_time + timedelta(seconds=5)).isoformat(),
                        "event_type": "anomalous_login",
                    },
                }
            ]
        }
    }

    def crashing_workflow(state):
        raise RuntimeError("Workflow failed during graph execution")

    mock_uow_ctx.checkpoints.record_failure.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        retry_count=1,
        status="RETRYING",
    )

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
        workflow_invoker=crashing_workflow,
    )

    with patch("zylar.ingestion.engine.detect_anomalies_node", return_value={"anomalies": [{"src_ip": "1.1.1.1"}]}):
        result = worker.poll_and_process_batch()

    assert result.status == "TRANSIENT_FAILURE"
    # Checkpoint must NOT advance on workflow failure
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_not_called()
    mock_uow_ctx.checkpoints.record_failure.assert_called_once()
