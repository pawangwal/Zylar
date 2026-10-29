from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from agents.report_agent import compute_canonical_batch_fingerprint
from agents.risk_agent import calculate_risk_node

from zylar.persistence.exceptions import IdempotencyConflictError


def test_calculate_risk_empty():
    state = {"attack_classification": "None", "anomalies": []}
    result = calculate_risk_node(state)
    assert result["risk_score"] == 0
    assert result["risk_category"] == "Low"


def test_calculate_risk_asset_criticality_ports():
    # SSH port 22 -> criticality 90
    ssh_state = {
        "attack_classification": "Brute Force",
        "anomalies": [
            {"source_ip": "198.51.100.22", "user": "root", "destination_port": 22} for _ in range(5)
        ],
        "graph_centrality": 20.0,
    }
    ssh_result = calculate_risk_node(ssh_state)
    assert ssh_result["asset_criticality"] == 90

    # Web port 443 -> criticality 70
    web_state = {
        "attack_classification": "Brute Force",
        "anomalies": [
            {"source_ip": "198.51.100.22", "user": "admin", "destination_port": 443}
            for _ in range(5)
        ],
        "graph_centrality": 20.0,
    }
    web_result = calculate_risk_node(web_state)
    assert web_result["asset_criticality"] == 70

    # Non-critical port 8080 -> criticality 50
    custom_state = {
        "attack_classification": "Brute Force",
        "anomalies": [
            {"source_ip": "198.51.100.22", "user": "admin", "destination_port": 8080}
            for _ in range(5)
        ],
        "graph_centrality": 20.0,
    }
    custom_result = calculate_risk_node(custom_state)
    assert custom_result["asset_criticality"] == 50


def test_calculate_risk_canonical_user_propagation():
    state = {
        "attack_classification": "Brute Force",
        "anomalies": [{"source_ip": "10.0.0.1", "user": "target_user", "destination_port": 22}],
        "graph_centrality": 10.0,
    }
    result = calculate_risk_node(state)
    assert "risk_score" in result
    assert "historical_recurrence" in result


def test_calculate_risk_score_reproducibility():
    state = {
        "attack_classification": "Ransomware",
        "anomalies": [
            {"source_ip": "10.0.0.99", "user": "user_a", "destination_port": 445} for _ in range(10)
        ],
        "graph_centrality": 35.0,
    }
    with patch("agents.risk_agent.get_historical_recurrence_factor", return_value=15):
        r1 = calculate_risk_node(state)
        r2 = calculate_risk_node(state)
        assert r1["risk_score"] == r2["risk_score"]
        assert r1["risk_category"] == r2["risk_category"]


def test_calculate_risk_replay_reuse_matching_incident():
    state = {
        "idempotency_key": "batch:test-123",
        "attack_classification": "Brute Force",
        "anomalies": [{"source_ip": "10.0.0.1", "destination_port": 22}],
    }
    mock_existing = MagicMock()
    mock_existing.attack_classification = "Brute Force"
    mock_existing.anomalous_events_count = 1
    mock_existing.risk_score = 65
    mock_existing.risk_category = "High"
    mock_existing.threat_intel = {
        "risk_policy_version": "risk-policy-v1",
        "risk_breakdown": {"criticality": 90.0},
    }

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        result = calculate_risk_node(state)
        assert result["risk_score"] == 65
        assert result["risk_category"] == "High"
        assert result["asset_criticality"] == 90


def test_calculate_risk_replay_raises_on_classification_conflict():
    state = {
        "idempotency_key": "batch:test-conflict",
        "attack_classification": "Ransomware",
        "anomalies": [{"source_ip": "10.0.0.1"}],
    }
    mock_existing = MagicMock()
    mock_existing.incident_id = "ZYLAR-INC-1"
    mock_existing.attack_classification = "Brute Force"
    mock_existing.anomalous_events_count = 1

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        with pytest.raises(IdempotencyConflictError, match="classification mismatch"):
            calculate_risk_node(state)


def test_calculate_risk_replay_raises_on_events_count_conflict():
    state = {
        "idempotency_key": "batch:test-count-conflict",
        "attack_classification": "Port Scan",
        "anomalies": [{"source_ip": "10.0.0.1"}, {"source_ip": "10.0.0.2"}],
    }
    mock_existing = MagicMock()
    mock_existing.incident_id = "ZYLAR-INC-2"
    mock_existing.attack_classification = "Port Scan"
    mock_existing.anomalous_events_count = 5

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        with pytest.raises(IdempotencyConflictError, match="anomalous events count mismatch"):
            calculate_risk_node(state)


def test_calculate_risk_replay_raises_on_policy_version_conflict():
    state = {
        "idempotency_key": "batch:test-policy-conflict",
        "attack_classification": "Port Scan",
        "anomalies": [{"source_ip": "10.0.0.1"}],
    }
    mock_existing = MagicMock()
    mock_existing.incident_id = "ZYLAR-INC-3"
    mock_existing.attack_classification = "Port Scan"
    mock_existing.anomalous_events_count = 1
    mock_existing.threat_intel = {"risk_policy_version": "ancient-v0"}

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        with pytest.raises(IdempotencyConflictError, match="scoring policy version mismatch"):
            calculate_risk_node(state)


def test_calculate_risk_replay_raises_on_batch_fingerprint_mismatch():
    """Verifies that replay raises IdempotencyConflictError when classification and event count
    match, but one constituent event identity differs (batch fingerprint mismatch).
    """
    event_orig = {"source_ip": "10.0.0.1", "destination_port": 22, "raw_event_hash": "a" * 64}
    event_diff = {"source_ip": "10.0.0.2", "destination_port": 22, "raw_event_hash": "b" * 64}

    recorded_fp = compute_canonical_batch_fingerprint([event_orig])

    state = {
        "idempotency_key": "batch:test-fp-conflict",
        "attack_classification": "Brute Force",
        "anomalies": [event_diff],  # Same count (1), same classification, but different event!
    }

    mock_existing = MagicMock()
    mock_existing.incident_id = "ZYLAR-INC-FP-1"
    mock_existing.attack_classification = "Brute Force"
    mock_existing.anomalous_events_count = 1
    mock_existing.threat_intel = {
        "risk_policy_version": "risk-policy-v1",
        "batch_fingerprint": recorded_fp,
    }

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        with pytest.raises(
            IdempotencyConflictError, match="canonical batch identity fingerprint mismatch"
        ):
            calculate_risk_node(state)


def test_calculate_risk_replay_legacy_incident_explicit_unknown_policy():
    """Verifies that replaying a legacy incident lacking risk_policy_version explicitly marks
    its policy version as 'unknown-legacy-policy' rather than fabricating a match to the active policy.
    """
    event = {"source_ip": "10.0.0.1", "destination_port": 22}
    fp = compute_canonical_batch_fingerprint([event])

    state = {
        "idempotency_key": "batch:test-legacy-policy",
        "attack_classification": "Brute Force",
        "anomalies": [event],
    }

    mock_existing = MagicMock()
    mock_existing.incident_id = "ZYLAR-INC-LEGACY-1"
    mock_existing.attack_classification = "Brute Force"
    mock_existing.anomalous_events_count = 1
    mock_existing.risk_score = 65
    mock_existing.risk_category = "High"
    # Legacy threat_intel without risk_policy_version
    mock_existing.threat_intel = {
        "batch_fingerprint": fp,
        "risk_breakdown": {"criticality": 90.0},
    }

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        result = calculate_risk_node(state)
        assert result["risk_score"] == 65
        assert result["risk_category"] == "High"
        assert result["risk_policy_version"] == "unknown-legacy-policy"


def test_calculate_risk_replay_legacy_event_refs_hash_mismatch():
    """Verifies that legacy incidents without batch_fingerprint fall back to event_refs verification
    and raise IdempotencyConflictError on raw hash mismatch.
    """
    state = {
        "idempotency_key": "batch:test-legacy-refs-conflict",
        "attack_classification": "Port Scan",
        "anomalies": [{"source_ip": "10.0.0.1", "raw_event_hash": "a" * 64}],
    }

    mock_ref = MagicMock()
    mock_ref.raw_event_hash = "f" * 64

    mock_existing = MagicMock()
    mock_existing.incident_id = "ZYLAR-INC-LEGACY-2"
    mock_existing.attack_classification = "Port Scan"
    mock_existing.anomalous_events_count = 1
    mock_existing.threat_intel = {}  # No batch_fingerprint
    mock_existing.event_refs = [mock_ref]

    mock_repo = MagicMock()
    mock_repo.get_by_idempotency_key.return_value = mock_existing

    with (
        patch("zylar.persistence.database.DatabaseManager.get_session"),
        patch("zylar.persistence.repositories.IncidentRepository", return_value=mock_repo),
    ):
        with pytest.raises(IdempotencyConflictError, match="event reference hashes mismatch"):
            calculate_risk_node(state)


