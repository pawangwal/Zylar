from __future__ import annotations

from agents.correlation_agent import (
    MAX_GRAPH_NODES,
    build_threat_correlation_graph_node,
)


def test_correlation_empty_events():
    result = build_threat_correlation_graph_node({"anomalies": []})
    assert result == {"graph_centrality": 0.0}


def test_correlation_canonical_user_and_port():
    events = [
        {"source_ip": "10.0.0.99", "user": "analyst_bob", "destination_port": 22},
        {"source_ip": "10.0.0.99", "user": "analyst_bob", "destination_port": 80},
        {"source_ip": "10.0.0.99", "user": "analyst_bob", "destination_port": 443},
    ]
    result = build_threat_correlation_graph_node({"anomalies": events})
    assert "graph_centrality" in result
    assert result["graph_centrality"] > 0.0


def test_correlation_multi_port_scan():
    # An attacker scanning 20 different ports
    events = [
        {"source_ip": "203.0.113.45", "destination_port": port, "user": "system"}
        for port in range(20, 40)
    ]
    result = build_threat_correlation_graph_node({"anomalies": events})
    # High connection density should yield substantial centrality
    assert result["graph_centrality"] > 20.0


def test_correlation_legacy_username_compatibility():
    # Test that legacy 'username' still correlates if user is omitted
    events = [
        {"source_ip": "172.16.1.5", "username": "legacy_operator", "destination_port": 3389},
    ]
    result = build_threat_correlation_graph_node({"anomalies": events})
    assert result["graph_centrality"] > 0.0


def test_correlation_bounded_graph_size():
    # Generate 1000 events to trigger bounds
    massive_events = [
        {"source_ip": f"10.0.{i // 256}.{i % 256}", "destination_port": i + 1, "user": f"user_{i}"}
        for i in range(1000)
    ]
    result = build_threat_correlation_graph_node({"anomalies": massive_events})
    assert "graph_centrality" in result
    assert 0.0 <= result["graph_centrality"] <= 100.0
