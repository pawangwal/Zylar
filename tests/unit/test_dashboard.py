"""Unit tests for SOC dashboard resilient telemetry fetchers and safe rendering."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests
from dashboard.app import (
    escape_dot_identifier,
    fetch_backend_health,
    fetch_ingestion_status,
    fetch_metrics,
    parse_prometheus_metrics,
)


def test_fetch_backend_health_timeout():
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out")):
        res = fetch_backend_health("http://127.0.0.1:8000", timeout=1.0)
        assert res["reachable"] is False
        assert res["status"] == "unreachable"
        assert "timed out" in res["error"].lower()


def test_fetch_backend_health_ready():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "ready",
        "checks": {"elasticsearch": "healthy", "database": "healthy", "ollama": "healthy"},
        "timestamp": "2026-10-25T12:00:00Z",
    }
    with patch("requests.get", return_value=mock_resp):
        res = fetch_backend_health("http://127.0.0.1:8000")
        assert res["reachable"] is True
        assert res["status"] == "ready"
        assert res["checks"]["elasticsearch"] == "healthy"


def test_fetch_backend_health_503_unhealthy():
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_resp.json.return_value = {
        "status": "unhealthy",
        "checks": {"elasticsearch": "unhealthy", "database": "unhealthy"},
        "timestamp": "2026-10-25T12:00:00Z",
    }
    with patch("requests.get", return_value=mock_resp):
        res = fetch_backend_health("http://127.0.0.1:8000")
        assert res["reachable"] is True
        assert res["status"] == "unhealthy"
        assert res["checks"]["database"] == "unhealthy"


def test_fetch_ingestion_status_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "stream_id": "elasticsearch-soc-events",
        "status": "HEALTHY",
        "lag_seconds": 12.4,
        "dead_letters_count": 0,
        "events_processed_count": 1500,
    }
    with patch("requests.get", return_value=mock_resp):
        res = fetch_ingestion_status("http://127.0.0.1:8000", auth_headers={"Authorization": "Bearer test"})
        assert res["status"] == "HEALTHY"
        assert res["lag_seconds"] == 12.4
        assert res["dead_letters_count"] == 0


def test_fetch_ingestion_status_timeout():
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Ingestion timeout")):
        res = fetch_ingestion_status("http://127.0.0.1:8000", auth_headers={})
        assert res["status"] == "unreachable"
        assert "timeout" in res["error"].lower()


def test_fetch_metrics_and_parse_prometheus():
    prom_text = (
        "# HELP zylar_events_received_total Total number of events received.\n"
        "# TYPE zylar_events_received_total counter\n"
        "zylar_events_received_total 120\n"
        "# HELP zylar_events_processed_total Total number of events processed.\n"
        "# TYPE zylar_events_processed_total counter\n"
        "zylar_events_processed_total 100\n"
        "# HELP zylar_events_deduplicated_total Total number of duplicate events filtered.\n"
        "# TYPE zylar_events_deduplicated_total counter\n"
        "zylar_events_deduplicated_total 15\n"
        "# HELP zylar_events_quarantined_total Total number of poison events quarantined.\n"
        "# TYPE zylar_events_quarantined_total counter\n"
        "zylar_events_quarantined_total 5\n"
        'zylar_workflow_executions_total{status="success"} 10\n'
        'zylar_workflow_executions_total{status="failed"} 1\n'
        'zylar_detection_rules_fired_total{rule="RULE_BRUTE_FORCE_AUTH"} 5\n'
        'zylar_detection_rules_fired_total{rule="RULE_PORT_SCAN_REJECT"} 3\n'
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = prom_text
    with patch("requests.get", return_value=mock_resp):
        raw = fetch_metrics("http://127.0.0.1:8000")
        assert "zylar_events_received_total 120" in raw

        parsed = parse_prometheus_metrics(raw)
        assert parsed["events_received"] == 120
        assert parsed["events_processed"] == 100
        assert parsed["events_deduplicated"] == 15
        assert parsed["events_quarantined"] == 5
        assert parsed["workflows"]["success"] == 10
        assert parsed["workflows"]["failed"] == 1
        assert parsed["rules_fired"]["RULE_BRUTE_FORCE_AUTH"] == 5
        assert parsed["rules_fired"]["RULE_PORT_SCAN_REJECT"] == 3


def test_escape_dot_identifier_sanitization():
    assert escape_dot_identifier("") == ""
    assert escape_dot_identifier("normal_user") == "normal_user"

    # Quotes, backslashes, newlines
    evil_label = 'admin"\\nbreakout'
    escaped = escape_dot_identifier(evil_label)
    assert '\\"' in escaped
    assert "\\\\" in escaped

    # Injection attempts
    injection = '10.0.0.1"; drop graph; --'
    cleaned = escape_dot_identifier(injection)
    assert "drop graph" not in cleaned.lower()


def test_parse_prometheus_metrics_unavailable():
    parsed = parse_prometheus_metrics("")
    assert parsed["status"] == "unavailable"
    assert parsed["events_received"] is None
    assert parsed["events_processed"] is None
    assert parsed["events_deduplicated"] is None
    assert parsed["events_quarantined"] is None

    parsed_none = parse_prometheus_metrics(None)
    assert parsed_none["status"] == "unavailable"
    assert parsed_none["events_received"] is None


def test_fetch_threat_graph_success_and_timeout():
    from dashboard.app import fetch_threat_graph

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "dot_graph": 'graph { "192.168.1.10" -- "443"; }',
        "total_nodes": 2,
        "total_edges": 1,
        "top_entities": ["192.168.1.10", "443"],
        "centrality_score": 50.0,
        "truncated": False,
    }
    with patch("requests.get", return_value=mock_resp):
        res = fetch_threat_graph("http://127.0.0.1:8000", auth_headers={"Authorization": "Bearer t"})
        assert res["status"] == "available"
        assert res["total_nodes"] == 2
        assert res["total_edges"] == 1
        assert res["centrality_score"] == 50.0
        assert "192.168.1.10" in res["dot_graph"]

    with patch("requests.get", side_effect=requests.exceptions.Timeout("Graph timeout")):
        res_to = fetch_threat_graph("http://127.0.0.1:8000", auth_headers={})
        assert res_to["status"] == "unavailable"
        assert res_to["total_nodes"] == 0

    mock_err_resp = MagicMock()
    mock_err_resp.status_code = 502
    with patch("requests.get", return_value=mock_err_resp):
        res_502 = fetch_threat_graph("http://127.0.0.1:8000", auth_headers={})
        assert res_502["status"] == "unavailable"
        assert "502" in res_502["error"]

