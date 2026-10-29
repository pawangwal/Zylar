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
        "# HELP zylar_ingested_events_total Total number of normalized events received.\n"
        "# TYPE zylar_ingested_events_total counter\n"
        "zylar_ingested_events_total 120\n"
        "# HELP zylar_deduplicated_events_total Total number of duplicate events filtered.\n"
        "# TYPE zylar_deduplicated_events_total counter\n"
        "zylar_deduplicated_events_total 15\n"
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
        assert "zylar_ingested_events_total 120" in raw

        parsed = parse_prometheus_metrics(raw)
        assert parsed["ingested_total"] == 120
        assert parsed["deduplicated_total"] == 15
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
