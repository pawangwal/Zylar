from __future__ import annotations

import pytest
from pydantic import ValidationError

from zylar.analysis.correlation_service import (
    CorrelationGraphResult,
    build_correlation_graph,
)


def test_build_correlation_graph_empty():
    res = build_correlation_graph([])
    assert isinstance(res, CorrelationGraphResult)
    assert res.centrality_score == 0.0
    assert res.node_count == 0
    assert res.edge_count == 0
    assert res.top_entities == ()
    assert "strict graph" in res.dot_representation


def test_build_correlation_graph_escapes_malicious_labels():
    events = [
        {
            "source_ip": "10.0.0.1\"; drop graph; --",
            "user": "evil\nuser\"withquote\x00andcontrol",
            "destination_port": 22,
        }
    ]
    res = build_correlation_graph(events)
    # Quotes and newlines must be safely escaped in the generated DOT output
    assert '\\"' in res.dot_representation
    assert "\\n" in res.dot_representation
    # Unprintable control characters must be stripped
    assert "\x00" not in res.dot_representation
    # Data identifiers must be preserved as data rather than arbitrarily truncated
    assert "drop graph" in res.dot_representation
    # Verify quotes are escaped so they cannot break out of string literal delimiter
    assert '"IP:10.0.0.1\\"; drop graph; --"' in res.dot_representation


def test_build_correlation_graph_bounds_limits():
    events = [
        {"source_ip": f"10.0.0.{i}", "user": f"user_{i}", "destination_port": 80}
        for i in range(500)
    ]
    res = build_correlation_graph(events, max_nodes=50, max_edges=60)
    assert res.node_count <= 50
    assert res.edge_count <= 60


def test_build_correlation_graph_canonical_entity_edges():
    events = [
        {"source_ip": "192.168.1.10", "user": "alice", "destination_port": 22},
        {"source_ip": "192.168.1.10", "username": "bob", "destination_port": 443},
    ]
    res = build_correlation_graph(events)
    assert res.node_count >= 4
    assert res.edge_count >= 3
    assert res.centrality_score > 0.0
    assert any("IP:192.168.1.10" in e for e in res.top_entities)


def test_correlation_graph_result_is_immutable():
    res = build_correlation_graph([])
    with pytest.raises((TypeError, ValidationError)):
        res.centrality_score = 50.0  # type: ignore[misc]

    assert isinstance(res.top_entities, tuple)
    with pytest.raises(AttributeError):
        res.top_entities.append("IP:10.0.0.1")  # type: ignore[attr-defined]


def test_correlation_graph_truncation_telemetry():
    # 1. Non-truncated scenario
    events = [{"source_ip": "10.0.0.1", "user": "alice", "destination_port": 22}]
    res = build_correlation_graph(events)
    assert res.input_event_count == 1
    assert res.processed_event_count == 1
    assert res.event_limit_reached is False
    assert res.node_limit_reached is False
    assert res.edge_limit_reached is False
    assert res.is_truncated is False

    # 2. Event limit truncation (> 500 events)
    large_events = [
        {"source_ip": f"10.0.0.{i % 250}", "user": f"user_{i}", "destination_port": 80}
        for i in range(550)
    ]
    res_large = build_correlation_graph(large_events)
    assert res_large.input_event_count == 550
    assert res_large.event_limit_reached is True
    assert res_large.is_truncated is True

    # 3. Node limit truncation
    res_node_capped = build_correlation_graph(large_events, max_nodes=5, max_edges=100)
    assert res_node_capped.node_limit_reached is True
    assert res_node_capped.is_truncated is True

