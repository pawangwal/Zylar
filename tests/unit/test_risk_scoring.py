from __future__ import annotations

from unittest.mock import patch

from agents.risk_agent import calculate_risk_node


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
