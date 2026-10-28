from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from log_generator.simulate_attacks import (
    generate_deterministic_benign_events,
    generate_deterministic_brute_force,
)
from orchestrator.workflow_graph import build_workflow


@pytest.fixture
def isolated_reports_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolates report generation to a temporary directory."""
    temp_reports = tmp_path / "reports"
    temp_reports.mkdir(parents=True, exist_ok=True)
    import agents.report_agent as ra

    monkeypatch.setattr(ra, "REPORTS_DIR", temp_reports)
    return temp_reports


def test_workflow_integration_empty_inputs(isolated_reports_dir: Path):
    """Verifies that all 8 nodes execute gracefully when input logs are empty."""
    graph = build_workflow()
    initial_state = {"raw_logs": []}

    final_state = graph.invoke(initial_state)

    # State propagation checks across all 8 nodes
    assert final_state.get("parsed_events") == []
    assert final_state.get("anomalies") == []
    assert final_state.get("threat_intel", {}).get("status") == "No anomalies found"
    assert final_state.get("attack_classification") == "None"
    assert final_state.get("graph_centrality") == 0.0
    assert final_state.get("risk_score") == 0
    assert final_state.get("risk_category") == "Low"
    assert final_state.get("mitigation_plan") == ["Monitor logs for future suspicious activity."]
    assert final_state.get("incident_id") == "None"
    assert final_state.get("report_content") == {}


def test_workflow_integration_benign_logs(isolated_reports_dir: Path):
    """Verifies workflow execution on benign logs with canonical field validation."""
    benign_raw = generate_deterministic_benign_events(count=10)
    graph = build_workflow()

    # Even if classifier LLM is invoked, mock ollama.Client to avoid external calls
    with patch("ollama.Client"):
        final_state = graph.invoke(
            {
                "raw_logs": benign_raw,
                "idempotency_key": f"test-benign-{uuid.uuid4().hex[:8]}",
            }
        )

    parsed = final_state.get("parsed_events", [])
    assert len(parsed) == 10

    # Verify canonical event contracts on parsed state
    for event in parsed:
        assert "event_id" in event and event["event_id"]
        assert "timestamp" in event and event["timestamp"]
        assert event["event_type"] == "web_access"
        assert event["source_ip"] is not None
        assert event["user"] in {"alice", "bob", "charlie"}
        assert len(event["raw_event_hash"]) == 64


def test_workflow_integration_attack_logs_with_controlled_dependencies(
    isolated_reports_dir: Path,
):
    """Verifies end-to-end execution of all 8 nodes with controlled AI dependencies."""
    # Provide background normal events + brute force attack events so Isolation Forest identifies outliers
    benign_background = generate_deterministic_benign_events(count=30)
    attack_raw = generate_deterministic_brute_force(count=15)
    all_logs = benign_background + attack_raw
    graph = build_workflow()

    # Controlled mock for Ollama (threat intel and mitigation)
    mock_ollama_client = MagicMock()

    def mock_ollama_chat(*args, **kwargs):
        messages = kwargs.get("messages", [])
        content_prompt = messages[-1]["content"] if messages else ""
        if "Threat Intelligence" in content_prompt:
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Distributed SSH brute force detected against root account.",
                            "attacker_ips": ["198.51.100.22"],
                            "targeted_users": ["root"],
                        }
                    )
                }
            }
        elif "Autonomous Cybersecurity Responder" in content_prompt:
            return {
                "message": {
                    "content": json.dumps(
                        [
                            "Block IP 198.51.100.22 on edge firewall",
                            "Enforce multi-factor authentication on root account",
                            "Audit SSH authorized_keys file",
                        ]
                    )
                }
            }
        elif "Attack Classification" in content_prompt:
            return {"message": {"content": json.dumps({"category": "Brute Force"})}}
        return {"message": {"content": "{}"}}

    mock_ollama_client.chat.side_effect = mock_ollama_chat

    with patch("ollama.Client", return_value=mock_ollama_client):
        final_state = graph.invoke(
            {
                "raw_logs": all_logs,
                "idempotency_key": f"test-attack-ctrl-{uuid.uuid4().hex[:8]}",
            }
        )

    # Node 1: analyze_logs
    assert len(final_state.get("parsed_events", [])) == 45

    # Node 2: detect_anomalies
    anomalies = final_state.get("anomalies", [])
    assert len(anomalies) > 0

    # Node 3: extract_threat_intel
    threat_intel = final_state.get("threat_intel", {})
    assert "Distributed SSH brute force" in threat_intel.get("summary", "")
    assert "198.51.100.22" in threat_intel.get("attacker_ips", [])

    # Node 4: classify_attack
    assert final_state.get("attack_classification") == "Brute Force"

    # Node 5: build_correlation_graph
    assert final_state.get("graph_centrality", 0.0) >= 0.0

    # Node 6: calculate_risk
    assert final_state.get("risk_score", 0) > 0
    assert final_state.get("risk_category") in {"Medium", "High", "Critical"}

    # Node 7: generate_mitigation
    mitigations = final_state.get("mitigation_plan", [])
    assert len(mitigations) == 3
    assert "Block IP 198.51.100.22 on edge firewall" in mitigations[0]

    # Node 8: generate_report
    incident_id = final_state.get("incident_id")
    assert incident_id is not None
    assert incident_id.startswith("ZYLAR-INC-")

    # Verify JSON and PDF artifacts created in isolated directory
    json_path = isolated_reports_dir / f"{incident_id}.json"
    pdf_path = isolated_reports_dir / f"{incident_id}.pdf"
    assert json_path.exists(), f"Report JSON not found at {json_path}"
    assert pdf_path.exists(), f"Report PDF not found at {pdf_path}"

    with open(json_path) as f:
        report_data = json.load(f)
    assert report_data["incident_id"] == incident_id
    assert report_data["attack_classification"] == "Brute Force"


def test_workflow_integration_deterministic_fallback_on_llm_failure(
    isolated_reports_dir: Path,
):
    """Verifies that the workflow falls back gracefully and deterministically when AI services fail."""
    benign_background = generate_deterministic_benign_events(count=30)
    attack_raw = generate_deterministic_brute_force(count=15)
    all_logs = benign_background + attack_raw
    graph = build_workflow()

    # Simulate completely offline / failing Ollama
    mock_failing_ollama = MagicMock()
    mock_failing_ollama.chat.side_effect = ConnectionRefusedError(
        "Ollama service unreachable on http://127.0.0.1:11434"
    )

    with patch("ollama.Client", return_value=mock_failing_ollama):
        final_state = graph.invoke(
            {
                "raw_logs": all_logs,
                "idempotency_key": f"test-attack-fallback-{uuid.uuid4().hex[:8]}",
            }
        )

    # Workflow must complete all 8 nodes without crashing
    assert final_state.get("attack_classification") == "Brute Force"

    # Threat intel should record the fallback error reason
    threat_intel = final_state.get("threat_intel", {})
    assert "Error parsing local LLM response" in threat_intel.get("summary", "")

    # Mitigation plan must use deterministic fallback steps
    mitigations = final_state.get("mitigation_plan", [])
    assert len(mitigations) >= 1
    assert "Block offending IP addresses manually" in mitigations[0]

    # Report should still be generated with fallback state
    incident_id = final_state.get("incident_id")
    assert incident_id is not None
    assert incident_id.startswith("ZYLAR-INC-")
    assert (isolated_reports_dir / f"{incident_id}.json").exists()


def test_workflow_integration_quarantines_malformed_records(isolated_reports_dir: Path):
    """Verifies that malformed logs are quarantined while valid records proceed through all 8 nodes."""
    mixed_raw = [
        # Valid event
        {
            "event_id": "good-001",
            "timestamp": "2026-10-25T14:00:00Z",
            "event_type": "network",
            "source_ip": "10.0.0.1",
        },
        # Malformed event: invalid IP
        {
            "event_id": "bad-001",
            "timestamp": "2026-10-25T14:01:00Z",
            "event_type": "network",
            "source_ip": "999.888.777.666",
        },
        # Malformed event: missing timestamp
        {
            "event_id": "bad-002",
            "event_type": "network",
        },
        # Valid event
        {
            "event_id": "good-002",
            "timestamp": "2026-10-25T14:02:00Z",
            "event_type": "network",
            "source_ip": "10.0.0.2",
        },
    ]

    graph = build_workflow()

    with patch("ollama.Client"):
        final_state = graph.invoke(
            {
                "raw_logs": mixed_raw,
                "idempotency_key": f"test-quarantine-{uuid.uuid4().hex[:8]}",
            }
        )

    parsed = final_state.get("parsed_events", [])
    quarantined = final_state.get("quarantined_events", [])

    assert len(parsed) == 2
    assert len(quarantined) == 2
    assert parsed[0]["event_id"] == "good-001"
    assert parsed[1]["event_id"] == "good-002"

    assert quarantined[0]["batch_index"] == 1
    assert "Invalid IP address" in quarantined[0]["error_reason"]
    assert quarantined[1]["batch_index"] == 2
