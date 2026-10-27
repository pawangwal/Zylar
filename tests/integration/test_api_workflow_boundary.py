from __future__ import annotations

from unittest.mock import MagicMock, patch

from api.main import app
from fastapi.testclient import TestClient

from zylar.core.security import Role, create_access_token

client = TestClient(app)
auth_headers = {"Authorization": f"Bearer {create_access_token('boundary_analyst', Role.ANALYST)}"}


def test_api_workflow_run_rejects_501_events():
    """Verifies that API boundary rejects requests exceeding 500 events with HTTP 422 before workflow execution."""
    events = [
        {
            "event_id": f"batch-{i:04d}",
            "timestamp": "2026-10-25T14:00:00Z",
            "event_type": "network",
        }
        for i in range(501)
    ]

    response = client.post("/api/workflow/run", json={"events": events}, headers=auth_headers)
    assert response.status_code == 422
    assert "500" in response.text or "at most 500" in response.text


def test_api_workflow_run_rejects_malformed_event():
    """Verifies that malformed events are rejected at the API boundary with HTTP 422."""
    bad_payload = {
        "events": [
            {
                "event_id": "bad-01",
                "timestamp": "not-a-timestamp",
                "event_type": "network",
            }
        ]
    }
    response = client.post("/api/workflow/run", json=bad_payload, headers=auth_headers)
    assert response.status_code == 422
    assert "Malformed ISO timestamp" in response.text


def test_api_workflow_run_rejects_duplicate_ids():
    """Verifies that duplicate event IDs are rejected by default with HTTP 422."""
    dup_payload = {
        "events": [
            {
                "event_id": "dup-1",
                "timestamp": "2026-10-25T14:00:00Z",
                "event_type": "network",
            },
            {
                "event_id": "dup-1",
                "timestamp": "2026-10-25T14:01:00Z",
                "event_type": "network",
            },
        ]
    }
    response = client.post("/api/workflow/run", json=dup_payload, headers=auth_headers)
    assert response.status_code == 422
    assert "Duplicate event IDs found" in response.text


def test_api_workflow_run_accepts_bounded_batch():
    """Verifies that a valid bounded batch of events executes through the workflow."""
    events = [
        {
            "event_id": f"evt-{i:03d}",
            "timestamp": "2026-10-25T14:00:00Z",
            "event_type": "network",
            "source_ip": "10.0.0.1",
        }
        for i in range(5)
    ]

    with patch("agents.classifier_agent.ChatOpenAI") as mock_chat:
        mock_chat.return_value.invoke.return_value = MagicMock(content="None")
        response = client.post("/api/workflow/run", json={"events": events}, headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert "attack_classification" in data
    assert "risk_score" in data
    assert "mitigation_plan" in data
