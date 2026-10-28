from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from agents.report_agent import generate_report_node
from elasticsearch.exceptions import ConnectionError as ESConnectionError

from zylar.ingestion.engine import CheckpointedIngestionWorker
from zylar.persistence.dtos import IncidentCreate
from zylar.persistence.exceptions import StaleLeaseError
from zylar.persistence.models import IngestionCheckpointModel


@pytest.fixture
def mock_uow_ctx():
    """Mocks UnitOfWork context manager and checkpoint repository."""
    with patch("zylar.ingestion.engine.UnitOfWork") as mock_uow_cls:
        mock_uow = MagicMock()
        mock_uow_cls.return_value.__enter__.return_value = mock_uow
        yield mock_uow


def test_worker_lease_not_acquired(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (False, 0)
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


def test_worker_lease_not_acquired_causes_zero_es_calls(mock_uow_ctx):
    # Even with non-zero generation (e.g. held by another worker), (False, 5) must prevent ES calls
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (False, 5)
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
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=now,
        last_processed_id="doc-100",
        lease_generation=1,
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
    mock_uow_ctx.checkpoints.release_lease.assert_called_once_with("test-stream", "test-worker", 1)
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_not_called()


def test_worker_search_after_pagination(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 2)
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id="doc-previous-last",
        lease_generation=2,
    )

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": []}}

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
    )

    worker.poll_and_process_batch()
    mock_es.search.assert_called_once()
    _, kwargs = mock_es.search.call_args
    body = kwargs.get("body", {})

    # Compound sort and search_after cursor check
    assert body.get("sort") == [
        {"timestamp": {"order": "asc"}},
        {"event_id.keyword": {"order": "asc", "unmapped_type": "keyword"}},
    ]
    assert body.get("search_after") == [watermark_time.isoformat(), "doc-previous-last"]


def test_worker_tie_breaker_skips_processed_events(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id="doc-002",
        lease_generation=1,
    )

    mock_es = MagicMock()
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
        lease_generation=1,
        lease_seconds=60,
    )
    mock_uow_ctx.checkpoints.release_lease.assert_called_once_with("test-stream", "test-worker", 1)


def test_worker_quarantines_poison_events(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id=None,
        lease_generation=1,
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
    # Checkpoint advanced with generation token
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_called_once_with(
        stream_id="test-stream",
        new_timestamp=valid_time,
        last_id="doc-valid-1",
        processed_count=1,
        worker_id="test-worker",
        lease_generation=1,
        lease_seconds=60,
    )
    mock_uow_ctx.checkpoints.release_lease.assert_called_once_with("test-stream", "test-worker", 1)


def test_worker_poison_event_at_boundary_advances_cursor(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 3)
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id=None,
        lease_generation=3,
    )

    mock_es = MagicMock()
    # Only a poison event exists in this batch
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-poison-boundary",
                    "_source": {"timestamp": "CORRUPT_TIMESTAMP", "data": "bad"},
                }
            ]
        }
    }

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "QUARANTINED"
    assert result.dead_letters_count == 1
    assert result.events_processed == 0
    # Cursor advances past poison ID to prevent infinite replay
    assert result.checkpoint_id == "doc-poison-boundary"

    mock_uow_ctx.checkpoints.quarantine_events.assert_called_once()
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_called_once_with(
        stream_id="test-stream",
        new_timestamp=watermark_time,
        last_id="doc-poison-boundary",
        processed_count=0,
        worker_id="test-worker",
        lease_generation=3,
        lease_seconds=60,
    )
    mock_uow_ctx.checkpoints.release_lease.assert_called_once_with("test-stream", "test-worker", 3)


def test_worker_atomic_transaction_persists_incident_and_checkpoint(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        last_processed_id=None,
        lease_generation=1,
    )

    valid_time = watermark_time + timedelta(seconds=10)
    mock_es = MagicMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "doc-incident-1",
                    "_source": {
                        "timestamp": valid_time.isoformat(),
                        "event_type": "brute_force",
                        "source_ip": "10.0.0.5",
                        "username": "admin",
                    },
                }
            ]
        }
    }

    sample_dto = IncidentCreate(
        incident_id="ZYLAR-INC-12345",
        idempotency_key="batch:brute_force:12345",
        timestamp=valid_time,
        attack_classification="Brute Force",
        risk_score=80,
        risk_category="High",
        mitigation_plan=["Block IP 10.0.0.5"],
        threat_intel={},
        anomalous_events_count=1,
        status="NEW",
        event_refs=[],
        actor="zylar-pipeline",
        correlation_id="corr-123",
    )

    mock_invoker = MagicMock(
        return_value={
            "incident_dto": sample_dto,
            "contributing_ips": ["10.0.0.5"],
            "contributing_users": ["admin"],
            "report_content": {"incident_id": "ZYLAR-INC-12345"},
        }
    )

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
        workflow_invoker=mock_invoker,
    )

    with patch("zylar.ingestion.engine.save_report_artifacts") as mock_save_artifacts:
        result = worker.poll_and_process_batch()

    assert result.status == "SUCCESS"
    # Single UoW persists incident lifecycle AND advances checkpoint
    mock_uow_ctx.persist_incident_lifecycle.assert_called_once_with(
        sample_dto,
        source_ips=["10.0.0.5"],
        user_identifiers=["admin"],
    )
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_called_once_with(
        stream_id="test-stream",
        new_timestamp=valid_time,
        last_id="doc-incident-1",
        processed_count=1,
        worker_id="test-worker",
        lease_generation=1,
        lease_seconds=60,
    )
    mock_uow_ctx.checkpoints.release_lease.assert_called_once_with("test-stream", "test-worker", 1)
    mock_save_artifacts.assert_called_once()


def test_worker_transient_es_error_records_failure(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    now = datetime.now(UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=now,
        lease_generation=1,
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
    mock_uow_ctx.checkpoints.record_failure.assert_called_once_with(
        stream_id="test-stream",
        error="Connection error",
        worker_id="test-worker",
        lease_generation=1,
        max_retries=5,
        backoff_initial_seconds=2.0,
        backoff_factor=2.0,
        backoff_max_seconds=60.0,
    )


def test_worker_stale_lease_failure_handling(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    now = datetime.now(UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=now,
        lease_generation=1,
    )

    mock_es = MagicMock()
    mock_es.search.side_effect = ESConnectionError("ES timeout")

    # Another worker already bumped generation, so record_failure raises StaleLeaseError
    mock_uow_ctx.checkpoints.record_failure.side_effect = StaleLeaseError("Stale generation")

    worker = CheckpointedIngestionWorker(
        stream_id="test-stream",
        worker_id="test-worker",
        es_client=mock_es,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "PERMANENT_FAILURE"
    assert "Connection error" in (result.error or "")


def test_worker_workflow_exception_does_not_advance_checkpoint(mock_uow_ctx):
    mock_uow_ctx.checkpoints.acquire_lease.return_value = (True, 1)
    watermark_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_uow_ctx.checkpoints.get.return_value = IngestionCheckpointModel(
        stream_id="test-stream",
        last_processed_timestamp=watermark_time,
        lease_generation=1,
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

    def crashing_workflow(raw_logs, defer_persistence=True):
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

    with patch(
        "zylar.ingestion.engine.detect_anomalies_node",
        return_value={"anomalies": [{"src_ip": "1.1.1.1"}]},
    ):
        result = worker.poll_and_process_batch()

    assert result.status == "TRANSIENT_FAILURE"
    # Checkpoint must NOT advance on workflow failure
    mock_uow_ctx.checkpoints.advance_checkpoint.assert_not_called()
    mock_uow_ctx.checkpoints.record_failure.assert_called_once()


def test_report_agent_deferred_mode_does_not_open_unit_of_work():
    """Verifies defer_persistence=True returns validated IncidentCreate without touching DB."""
    anomalous_event = {
        "event_id": "test-evt-001",
        "timestamp": "2026-10-28T12:00:00Z",
        "source": "suricata",
        "source_ip": "192.168.1.50",
        "user": "test_admin",
        "raw_event_hash": "b" * 64,
    }
    state = {
        "candidate_incident_id": "ZYLAR-INC-TEST-DEFER",
        "anomalies": [anomalous_event],
        "attack_classification": "Privilege Escalation",
        "risk_score": 90,
        "risk_category": "Critical",
        "mitigation_plan": ["Revoke admin tokens"],
        "threat_intel": {"reputation": "malicious"},
        "contributing_ips": ["192.168.1.50"],
        "contributing_users": ["test_admin"],
        "defer_persistence": True,
    }

    with patch("agents.report_agent.UnitOfWork") as mock_uow_cls:
        result = generate_report_node(state)  # type: ignore[arg-type]

        mock_uow_cls.assert_not_called()
        assert result["incident_id"].startswith("ZYLAR-INC-")
        assert result["incident_dto"] is not None
        assert isinstance(result["incident_dto"], IncidentCreate)
        assert result["incident_dto"].incident_id == result["incident_id"]
        assert result["incident_dto"].risk_category == "Critical"
        assert "192.168.1.50" in result["contributing_ips"]
        assert "test_admin" in result["contributing_users"]


def test_report_agent_legacy_caller_persists_immediately():
    """Verifies default defer_persistence=False continues to persist via UnitOfWork."""
    anomalous_event = {
        "event_id": "test-evt-002",
        "timestamp": "2026-10-28T12:00:00Z",
        "source": "suricata",
        "source_ip": "192.168.1.51",
        "user": "test_user",
        "raw_event_hash": "c" * 64,
    }
    state = {
        "candidate_incident_id": "ZYLAR-INC-TEST-LEGACY",
        "anomalies": [anomalous_event],
        "attack_classification": "Lateral Movement",
        "risk_score": 70,
        "risk_category": "High",
        "mitigation_plan": ["Isolate host"],
        "threat_intel": {},
        "defer_persistence": False,
    }

    mock_lifecycle_result = MagicMock()
    mock_lifecycle_result.incident.incident_id = "ZYLAR-INC-SAVED-123"
    mock_lifecycle_result.incident.timestamp = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    mock_lifecycle_result.incident.attack_classification = "Lateral Movement"
    mock_lifecycle_result.incident.risk_category = "High"
    mock_lifecycle_result.incident.risk_score = 70
    mock_lifecycle_result.incident.threat_intel = {}
    mock_lifecycle_result.incident.mitigation_plan = ["Isolate host"]
    mock_lifecycle_result.incident.anomalous_events_count = 1
    mock_lifecycle_result.created = True

    with patch("agents.report_agent.UnitOfWork") as mock_uow_cls:
        mock_uow = MagicMock()
        mock_uow.persist_incident_lifecycle.return_value = mock_lifecycle_result
        mock_uow_cls.return_value.__enter__.return_value = mock_uow

        with patch("agents.report_agent.save_report_artifacts"):
            result = generate_report_node(state)  # type: ignore[arg-type]

        mock_uow_cls.assert_called_once()
        mock_uow.persist_incident_lifecycle.assert_called_once()
        assert result["incident_id"] == "ZYLAR-INC-SAVED-123"
        assert "incident_dto" not in result
