"""Phase 6 End-to-End Cross-Contract Integration Tests.

Validates the full detection-to-observability contract:
Normalized Events -> Deterministic Detection Rules -> Versioned Risk Scoring ->
Checkpointed Ingestion Worker -> Persistence & Reporting ->
Prometheus Operational Telemetry -> Canonical Threat Graph & Truncation Semantics.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from api.main import app
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from fastapi.testclient import TestClient
from sqlalchemy import text

from zylar.core.metrics import get_metrics_collector
from zylar.core.security import Role, create_access_token
from zylar.ingestion.engine import CheckpointedIngestionWorker
from zylar.persistence.database import get_database_manager
from zylar.persistence.dtos import IncidentCreate
from zylar.persistence.unit_of_work import UnitOfWork


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Yields a context-managed TestClient to ensure proper app lifespan and test isolation."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def clean_metrics_state():
    collector = get_metrics_collector()
    collector.reset()
    yield
    collector.reset()


@pytest.fixture(autouse=True)
def clean_db_state():
    """Cleans up any cross-contract test database state before and after each test."""
    db_mgr = get_database_manager()

    def _cleanup():
        with db_mgr.engine.connect() as conn:
            with conn.begin():
                conn.execute(
                    text(
                        "DELETE FROM dead_letter_events WHERE stream_id LIKE 'test-cc-%'"
                    )
                )
                conn.execute(
                    text(
                        "DELETE FROM ingestion_checkpoints WHERE stream_id LIKE 'test-cc-%'"
                    )
                )
                conn.execute(
                    text(
                        "DELETE FROM incidents WHERE incident_id LIKE 'ZYLAR-INC-CC-%' OR idempotency_key LIKE 'test-cc-%'"
                    )
                )
                conn.execute(
                    text(
                        "DELETE FROM audit_logs WHERE correlation_id LIKE 'test-cc-%'"
                    )
                )

    _cleanup()
    yield
    _cleanup()


@pytest.fixture
def analyst_token() -> str:
    return create_access_token(subject="analyst_user", role=Role.ANALYST)


def generate_brute_force_event_batch(
    src_ip: str = "192.168.1.88",
    user: str = "target_admin",
    count: int = 8,
    batch_id: str | None = None,
) -> list[dict[str, Any]]:
    """Generates a sequence of failed authentication events within a tight temporal window."""
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=UTC)
    bid = batch_id or uuid.uuid4().hex[:8]
    events = []
    for i in range(count):
        events.append(
            {
                "event_id": f"bf-{bid}-{i:03d}",
                "timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
                "event_type": "auth_failure",
                "source_ip": src_ip,
                "user": user,
                "status": "failed",
                "destination_port": 22,
                "details": f"Failed password attempt {i+1} for {user} from {src_ip}",
            }
        )
    return events


def generate_benign_event_batch(
    count: int = 5, batch_id: str | None = None
) -> list[dict[str, Any]]:
    """Generates standard legitimate HTTP web requests with distinct timestamps."""
    base_time = datetime(2026, 10, 25, 14, 0, 0, tzinfo=UTC)
    bid = batch_id or uuid.uuid4().hex[:8]
    events = []
    for i in range(count):
        events.append(
            {
                "event_id": f"benign-{bid}-{i:03d}",
                "timestamp": (base_time + timedelta(seconds=i * 20)).isoformat(),
                "event_type": "web_access",
                "source_ip": "10.0.0.15",
                "user": "developer_alice",
                "status": "success",
                "destination_port": 443,
                "details": f"GET /api/v1/health HTTP/1.1 200 OK (req {i})",
            }
        )
    return events


def test_api_workflow_cross_contract(client: TestClient, analyst_token: str):
    """Submits a labeled attack batch through the full API and asserts the cross-task contract."""
    attack_events = generate_brute_force_event_batch(count=7)
    headers = {
        "Authorization": f"Bearer {analyst_token}",
        "X-Correlation-ID": "test-cc-workflow-001",
    }

    mock_ollama_client = MagicMock()
    mock_ollama_client.chat.return_value = {
        "message": {
            "content": json.dumps(
                {
                    "summary": "Coordinated SSH brute force attack detected.",
                    "mitigation_plan": [
                        "Enforce temporary IP ban on source IP",
                        "Reset user credentials",
                    ],
                }
            )
        }
    }

    with patch("ollama.Client", return_value=mock_ollama_client):
        res = client.post(
            "/api/workflow/run",
            json={"events": attack_events},
            headers=headers,
        )

        assert res.status_code == 200, f"Workflow execution failed: {res.text}"
        data = res.json()

        assert data["incident_id"] is not None and data["incident_id"] != "None"
        assert data["attack_classification"] == "Brute Force"
        assert data["risk_score"] > 0
        assert data["risk_category"] in ("Medium", "High", "Critical")
        assert len(data["mitigation_plan"]) >= 1

    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    metrics_text = metrics_res.text

    assert "zylar_events_received_total 7" in metrics_text
    assert "zylar_events_processed_total 7" in metrics_text
    assert 'zylar_detection_rules_fired_total{rule="RULE_BRUTE_FORCE_AUTH"} 1' in metrics_text
    assert 'zylar_workflow_executions_total{status="success"} 1' in metrics_text
    assert "# TYPE zylar_workflow_execution_duration_seconds histogram" in metrics_text
    assert 'zylar_workflow_execution_duration_seconds_count{status="success"} 1' in metrics_text


def test_benign_api_workflow_cross_contract(client: TestClient, analyst_token: str):
    """Submits benign traffic and asserts 0 false positive triggers and 0 risk score."""
    benign_events = generate_benign_event_batch(count=5)
    headers = {
        "Authorization": f"Bearer {analyst_token}",
        "X-Correlation-ID": "test-cc-benign-001",
    }

    with patch("ollama.Client"):
        res = client.post(
            "/api/workflow/run",
            json={"events": benign_events},
            headers=headers,
        )
        assert res.status_code == 200
        data = res.json()

        assert data["attack_classification"] == "None"
        assert data["risk_score"] == 0
        assert data["risk_category"] == "Low"

    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    metrics_text = metrics_res.text

    assert "zylar_events_received_total 5" in metrics_text
    assert "zylar_events_processed_total 5" in metrics_text
    assert "RULE_BRUTE_FORCE_AUTH" not in metrics_text
    assert "RULE_PORT_SCAN_REJECT" not in metrics_text
    assert "RULE_RANSOMWARE_INDICATOR" not in metrics_text


def test_worker_ingestion_cross_contract_successful_batch():
    """Validates full CheckpointedIngestionWorker integration cycle:

    Elasticsearch polling -> Watermark advancement -> Atomic PostgreSQL persistence ->
    Prometheus metrics collection.
    """
    stream_id = f"test-cc-worker-{uuid.uuid4().hex[:8]}"
    worker_id = f"worker-test-{uuid.uuid4().hex[:8]}"
    t0 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=15)

    hits = [
        {
            "_id": "doc-cc-01",
            "_source": {
                "event_id": "evt-cc-01",
                "timestamp": t0.isoformat(),
                "event_type": "auth_failure",
                "source_ip": "198.51.100.20",
                "user": "test_admin",
                "destination_port": 22,
            },
            "sort": [t0.isoformat(), "evt-cc-01"],
        },
        {
            "_id": "doc-cc-02",
            "_source": {
                "event_id": "evt-cc-02",
                "timestamp": t1.isoformat(),
                "event_type": "auth_failure",
                "source_ip": "198.51.100.20",
                "user": "test_admin",
                "destination_port": 22,
            },
            "sort": [t1.isoformat(), "evt-cc-02"],
        },
    ]

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": hits}}

    incident_id = f"ZYLAR-INC-CC-{uuid.uuid4().hex[:8]}"
    idem_key = f"test-cc-{uuid.uuid4().hex[:8]}"

    def mock_workflow(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "incident_dto": IncidentCreate(
                incident_id=incident_id,
                idempotency_key=idem_key,
                timestamp=t1,
                attack_classification="Brute Force",
                risk_score=75,
                risk_category="High",
                mitigation_plan=["Block IP 198.51.100.20", "Reset admin credentials"],
                anomalous_events_count=2,
            ),
            "contributing_ips": ["198.51.100.20"],
            "contributing_users": ["test_admin"],
            "rule_matches": [{"rule_id": "RULE_BRUTE_FORCE_AUTH"}],
        }

    session_factory = get_database_manager().session_factory

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        uow.checkpoints.get_or_create(stream_id, default_start_time=t0 - timedelta(seconds=1))
        uow.commit()

    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id=worker_id,
        es_client=mock_es,
        session_factory=session_factory,
        workflow_invoker=mock_workflow,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "SUCCESS"
    assert result.events_read == 2
    assert result.events_processed == 2
    assert result.checkpoint_timestamp == t1
    assert result.checkpoint_id == "evt-cc-02"

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        cp = uow.checkpoints.get(stream_id)
        assert cp is not None
        assert cp.last_processed_timestamp == t1
        assert cp.last_processed_id == "evt-cc-02"
        assert cp.events_processed_count == 2
        assert cp.lease_owner is None

        assert uow.incidents is not None
        inc = uow.incidents.get_by_incident_id(incident_id)
        assert inc is not None
        assert inc.idempotency_key == idem_key
        assert inc.risk_score == 75

    collector = get_metrics_collector()
    assert collector._events_received >= 2
    assert collector._events_processed >= 2
    assert collector._rules_fired.get("RULE_BRUTE_FORCE_AUTH", 0) >= 1
    assert collector._workflow_counts.get("success", 0) >= 1

    prom_text = collector.get_prometheus_text()
    assert "zylar_events_received_total 2" in prom_text
    assert "zylar_events_processed_total 2" in prom_text


def test_worker_ingestion_cross_contract_replay_duplicate():
    """Validates that replaying an already-committed batch increments events_deduplicated and skips processing."""
    stream_id = f"test-cc-dedup-{uuid.uuid4().hex[:8]}"
    worker_id = f"worker-test-{uuid.uuid4().hex[:8]}"
    t0 = datetime(2026, 10, 25, 14, 0, 0, tzinfo=UTC)

    session_factory = get_database_manager().session_factory

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        uow.checkpoints.get_or_create(stream_id, default_start_time=t0)
        acquired, gen = uow.checkpoints.acquire_lease(stream_id, worker_id, default_start_time=t0)
        assert acquired is True
        uow.checkpoints.advance_checkpoint(
            stream_id=stream_id,
            new_timestamp=t0,
            last_id="evt-committed-01",
            processed_count=1,
            worker_id=worker_id,
            lease_generation=gen,
            lease_seconds=60,
        )
        uow.checkpoints.release_lease(stream_id, worker_id, gen)
        uow.commit()

    replayed_hits = [
        {
            "_id": "doc-dup-01",
            "_source": {
                "event_id": "evt-committed-01",
                "timestamp": t0.isoformat(),
                "source_ip": "10.0.0.1",
            },
            "sort": [t0.isoformat(), "evt-committed-01"],
        }
    ]

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": replayed_hits}}

    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id=worker_id,
        es_client=mock_es,
        session_factory=session_factory,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "IDLE"
    assert result.events_read == 1
    assert result.events_processed == 0

    collector = get_metrics_collector()
    assert collector._events_received >= 1
    assert collector._events_deduplicated >= 1
    assert collector._events_processed == 0

    prom_text = collector.get_prometheus_text()
    assert "zylar_events_deduplicated_total 1" in prom_text

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        cp = uow.checkpoints.get(stream_id)
        assert cp is not None
        assert cp.last_processed_timestamp == t0
        assert cp.last_processed_id == "evt-committed-01"
        assert cp.lease_owner is None


def test_worker_ingestion_cross_contract_poison_pill_quarantine():
    """Validates that unparseable or malformed events are quarantined to dead-letter store."""
    stream_id = f"test-cc-poison-{uuid.uuid4().hex[:8]}"
    worker_id = f"worker-test-{uuid.uuid4().hex[:8]}"

    poison_hits = [
        {
            "_id": "doc-poison-01",
            "_source": {
                "event_id": "bad-ts-01",
                "timestamp": "invalid-non-iso-timestamp",
                "source_ip": "10.0.0.2",
            },
            "sort": ["2026-10-25T14:00:00Z", "bad-ts-01"],
        },
        {
            "_id": "doc-poison-02",
            "_source": "this-is-not-a-dict",
            "sort": ["2026-10-25T14:00:05Z", "doc-poison-02"],
        },
    ]

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": poison_hits}}

    session_factory = get_database_manager().session_factory
    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id=worker_id,
        es_client=mock_es,
        session_factory=session_factory,
    )

    result = worker.poll_and_process_batch()
    assert result.status == "QUARANTINED"
    assert result.events_read == 2
    assert result.events_processed == 0
    assert result.dead_letters_count == 2

    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        dl_count = uow.checkpoints.get_dead_letter_count(stream_id)
        assert dl_count == 2

    collector = get_metrics_collector()
    assert collector._events_received >= 2
    assert collector._events_quarantined >= 2
    assert collector._events_processed == 0

    prom_text = collector.get_prometheus_text()
    assert "zylar_events_quarantined_total 2" in prom_text


def test_worker_error_recovery_clears_last_error():
    """Validates that worker records failures in _last_error and clears _last_error on recovery."""
    stream_id = f"test-cc-recovery-{uuid.uuid4().hex[:8]}"
    worker_id = f"worker-test-{uuid.uuid4().hex[:8]}"

    mock_es = MagicMock()
    mock_es.search.side_effect = ESConnectionError("Simulated Elasticsearch cluster connection failure")

    session_factory = get_database_manager().session_factory
    worker = CheckpointedIngestionWorker(
        stream_id=stream_id,
        worker_id=worker_id,
        es_client=mock_es,
        session_factory=session_factory,
        backoff_initial_seconds=0.0,
    )

    # 1. Failed cycle: _last_error should be set
    worker.run_poll_cycle()
    status1 = worker.get_worker_status()
    assert status1["last_error"] is not None
    assert "connection error" in status1["last_error"].lower()
    assert status1["last_failed_cycle"] is not None

    # Reset retry cooldown so worker can immediately re-acquire lease
    with UnitOfWork(session_factory) as uow:
        assert uow.checkpoints is not None
        cp = uow.checkpoints.get(stream_id)
        assert cp is not None
        cp.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
        uow.commit()

    # 2. Recovering cycle: mock recovers and returns IDLE
    mock_es.search.side_effect = None
    mock_es.search.return_value = {"hits": {"hits": []}}

    worker.run_poll_cycle()
    status2 = worker.get_worker_status()
    assert status2["last_error"] is None
    assert status2["last_successful_cycle"] is not None
    assert status2["last_failed_cycle"] is not None


def test_scheduler_status_lifecycle(client: TestClient, analyst_token: str):
    """Validates scheduler status reporting for active, stopped, and offline states."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Active: Lifespan context initialized the background scheduler
    res_active = client.get("/api/ingestion/status", headers=headers)
    assert res_active.status_code == 200
    data_active = res_active.json()
    assert "scheduler" in data_active
    sched_info = data_active["scheduler"]
    assert sched_info["status"] == "active"
    assert sched_info["running"] is True
    assert "worker_id" in sched_info

    # 2. Stopped: Scheduler shutdown marks status as stopped
    sched = getattr(app.state, "scheduler", None)
    assert sched is not None
    sched.shutdown(wait=False)
    res_stopped = client.get("/api/ingestion/status", headers=headers)
    assert res_stopped.status_code == 200
    data_stopped = res_stopped.json()
    assert data_stopped["scheduler"]["status"] == "stopped"
    assert data_stopped["scheduler"]["running"] is False

    # 3. Offline: When scheduler is not configured on app.state (e.g. API-only mode)
    original_sched = getattr(app.state, "scheduler", None)
    try:
        app.state.scheduler = None
        res_offline = client.get("/api/ingestion/status", headers=headers)
        assert res_offline.status_code == 200
        data_offline = res_offline.json()
        assert data_offline["scheduler"]["status"] == "offline"
        assert data_offline["scheduler"]["running"] is False
    finally:
        app.state.scheduler = original_sched


def test_threat_graph_upstream_error_semantics(client: TestClient, analyst_token: str):
    """Validates that search backend connection failures return HTTP 502 Bad Gateway."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    with patch(
        "elasticsearch.Elasticsearch.search",
        side_effect=ESConnectionError("Elasticsearch cluster unavailable"),
    ):
        res = client.get("/api/threat-graph?minutes=15", headers=headers)
        assert res.status_code == 502
        data = res.json()
        assert "error" in data
        assert "Failed to retrieve log telemetry from search backend" in data["error"]


def test_threat_graph_endpoint_truncation_telemetry(client: TestClient, analyst_token: str):
    """Validates canonical threat graph generation including explicit truncation telemetry flags."""
    headers = {"Authorization": f"Bearer {analyst_token}"}

    mock_hits = [
        {
            "_source": {
                "source_ip": "192.168.1.100",
                "user": "admin",
                "destination_port": 22,
                "timestamp": "2026-10-25T14:00:00Z",
            }
        },
        {
            "_source": {
                "source_ip": "192.168.1.100",
                "user": "root",
                "destination_port": 22,
                "timestamp": "2026-10-25T14:00:05Z",
            }
        },
    ]

    with patch(
        "elasticsearch.Elasticsearch.search", return_value={"hits": {"hits": mock_hits}}
    ):
        res_graph = client.get("/api/threat-graph?minutes=15", headers=headers)
        assert res_graph.status_code == 200
        graph_data = res_graph.json()

        assert "dot_graph" in graph_data
        assert "top_entities" in graph_data
        assert "centrality_score" in graph_data
        assert graph_data["total_nodes"] >= 2
        assert graph_data["total_edges"] >= 1

        assert graph_data["input_event_count"] == 2
        assert graph_data["processed_event_count"] == 2
        assert graph_data["event_limit_reached"] is False
        assert graph_data["node_limit_reached"] is False
        assert graph_data["edge_limit_reached"] is False
        assert graph_data["truncated"] is False
