from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from agents.risk_agent import calculate_risk_node
from api.main import app
from fastapi.testclient import TestClient
from log_generator.simulate_attacks import (
    generate_deterministic_benign_events,
    generate_deterministic_brute_force,
)
from orchestrator.workflow_graph import build_workflow
from sqlalchemy import create_engine, select, text

from zylar.core.security import Role, create_access_token
from zylar.core.settings import get_settings
from zylar.persistence.database import get_session
from zylar.persistence.models import (
    AuditLogModel,
    IncidentEventRefModel,
    IncidentModel,
    IPHistoryModel,
    RiskHistoryModel,
    UserHistoryModel,
)


def check_live_postgres() -> bool:
    settings = get_settings()
    try:
        engine = create_engine(str(settings.database_url), connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not check_live_postgres(),
    reason="PostgreSQL not reachable at configured ZYLAR_DATABASE_URL",
)


@pytest.fixture
def isolated_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    temp_dir = tmp_path / "reports"
    temp_dir.mkdir(parents=True, exist_ok=True)
    import agents.report_agent as ra

    monkeypatch.setattr(ra, "REPORTS_DIR", temp_dir)
    return temp_dir


def test_workflow_persists_incident_and_evidence_to_postgres(isolated_reports: Path):
    """Verifies that running the workflow on attack logs atomically persists the incident,

    constituent event references, risk history, audit log, and offender recurrence to PostgreSQL.
    """
    benign = generate_deterministic_benign_events(count=20)
    attack = generate_deterministic_brute_force(count=10)
    logs = benign + attack

    # Mock Ollama responses
    def mock_ollama_chat(*args, **kwargs):
        messages = kwargs.get("messages", [])
        prompt = messages[-1]["content"] if messages else ""
        if "Attack Classification" in prompt:
            return {"message": {"content": json.dumps({"category": "Brute Force"})}}
        elif "Threat Intelligence" in prompt:
            return {
                "message": {
                    "content": json.dumps({
                        "summary": "SSH brute force detected.",
                        "attacker_ips": ["198.51.100.22"],
                        "targeted_users": ["root"],
                    })
                }
            }
        else:
            return {"message": {"content": json.dumps(["Block IP 198.51.100.22", "Audit SSH"])}}

    mock_ollama = MagicMock()
    mock_ollama.chat.side_effect = mock_ollama_chat

    test_corr_id = f"test-corr-{uuid.uuid4().hex[:8]}"
    stable_idempotency_key = f"batch-replay-{uuid.uuid4().hex[:8]}"
    state_input = {
        "raw_logs": logs,
        "correlation_id": test_corr_id,
        "idempotency_key": stable_idempotency_key,
        "actor": "integration-test",
    }

    with patch("ollama.Client", return_value=mock_ollama):
        graph = build_workflow()
        final_state = graph.invoke(state_input)

    incident_id = final_state.get("incident_id")
    assert incident_id is not None
    assert incident_id.startswith("ZYLAR-INC-")

    # Verify atomic PostgreSQL persistence
    with get_session() as session:
        # 1. Incident record
        incident = session.execute(
            select(IncidentModel).where(IncidentModel.incident_id == incident_id)
        ).scalar_one_or_none()
        assert incident is not None
        assert incident.attack_classification == "Brute Force"
        assert incident.risk_score == final_state["risk_score"]
        assert incident.anomalous_events_count == len(final_state.get("anomalies", []))

        # 2. Constituent event references
        event_refs = session.execute(
            select(IncidentEventRefModel).where(IncidentEventRefModel.incident_id == incident.id)
        ).scalars().all()
        assert len(event_refs) > 0
        for ref in event_refs:
            assert ref.event_source is not None
            assert len(ref.raw_event_hash) == 64

        # 3. Risk history
        risk_hist = session.execute(
            select(RiskHistoryModel).where(RiskHistoryModel.incident_id == incident.id)
        ).scalars().all()
        assert len(risk_hist) >= 1
        assert risk_hist[0].risk_score == incident.risk_score

        # 4. Audit log
        audit = session.execute(
            select(AuditLogModel).where(AuditLogModel.incident_id == incident.id)
        ).scalar_one_or_none()
        assert audit is not None
        assert audit.action == "INCIDENT_CREATED"
        assert audit.actor == "integration-test"

        # 5. Offender history updated
        offender_ip = session.execute(
            select(IPHistoryModel).where(IPHistoryModel.ip_address == "198.51.100.22")
        ).scalar_one_or_none()
        assert offender_ip is not None
        initial_offense_count = offender_ip.offense_count
        assert initial_offense_count >= 1

    # Now verify idempotent replay: replaying the same state does NOT create duplicates or double count
    with patch("ollama.Client", return_value=mock_ollama):
        graph = build_workflow()
        replay_state = graph.invoke(state_input)
        assert replay_state.get("incident_id") is not None

    with get_session() as session:
        # Incident count for this idempotency key should still be exactly 1
        matching_incidents = session.execute(
            select(IncidentModel).where(IncidentModel.idempotency_key == stable_idempotency_key)
        ).scalars().all()
        assert len(matching_incidents) == 1

        # Offense count should NOT have incremented on idempotent replay
        recheck_offender = session.execute(
            select(IPHistoryModel).where(IPHistoryModel.ip_address == "198.51.100.22")
        ).scalar_one_or_none()
        assert recheck_offender is not None
        assert recheck_offender.offense_count == initial_offense_count



def test_risk_calculation_queries_postgres_offender_recurrence():
    """Verifies that calculate_risk_node reads recurrence counts from PostgreSQL and scales score."""
    target_ip = f"203.0.113.{uuid.uuid4().int % 200 + 10}"
    target_user = f"victim_{uuid.uuid4().hex[:6]}"

    with get_session() as session:
        session.add(
            IPHistoryModel(
                ip_address=target_ip,
                offense_count=5,
                last_seen=datetime.now(UTC),
                last_risk_score=80,
            )
        )
        session.add(
            UserHistoryModel(
                username=target_user,
                offense_count=3,
                last_seen=datetime.now(UTC),
                last_risk_score=80,
            )
        )
        session.commit()

    state = {
        "attack_classification": "Brute Force",
        "anomalies": [
            {
                "source_ip": target_ip,
                "user": target_user,
                "destination_port": 22,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        ],
        "graph_centrality": 10.0,
    }

    result = calculate_risk_node(state)
    # 5 + 3 = 8 offenses * 5 points = 40 historical recurrence
    assert result["historical_recurrence"] == 40
    assert result["risk_score"] > 0
    assert target_ip in result["contributing_ips"]
    assert target_user in result["contributing_users"]


def test_api_offenders_returns_postgres_records():
    """Verifies that the /api/offenders endpoint returns top offenders from PostgreSQL."""
    client = TestClient(app)
    viewer_token = create_access_token("viewer_test", Role.VIEWER)

    response = client.get(
        "/api/offenders?limit=10",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "top_ips" in data["data"]
    assert "top_users" in data["data"]
    assert isinstance(data["data"]["top_ips"], list)
    assert isinstance(data["data"]["top_users"], list)
