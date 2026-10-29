"""Tests for Prometheus operational metrics exposition endpoint and accumulator."""

from __future__ import annotations

import concurrent.futures

import pytest
from api.main import app
from fastapi.testclient import TestClient

from zylar.core.metrics import MetricsCollector, get_metrics_collector

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_collector():
    collector = get_metrics_collector()
    collector.reset()
    yield
    collector.reset()


def test_metrics_endpoint_returns_prometheus_format():
    collector = get_metrics_collector()
    collector.record_event_ingested(42)
    collector.record_event_deduplicated(7)
    collector.record_detection_rule_fired("RULE_BRUTE_FORCE_AUTH", count=3)
    collector.record_workflow_execution(status="success", duration_seconds=0.125)

    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    assert "version=0.0.4" in res.headers["content-type"]

    body = res.text
    assert "# HELP zylar_ingested_events_total" in body
    assert "# TYPE zylar_ingested_events_total counter" in body
    assert "zylar_ingested_events_total 42" in body

    assert "# HELP zylar_deduplicated_events_total" in body
    assert "zylar_deduplicated_events_total 7" in body

    assert 'zylar_detection_rules_fired_total{rule="RULE_BRUTE_FORCE_AUTH"} 3' in body
    assert 'zylar_workflow_executions_total{status="success"} 1' in body
    assert body.endswith("\n")


def test_metrics_endpoint_initial_empty_exposition():
    res = client.get("/metrics")
    assert res.status_code == 200
    body = res.text
    assert "zylar_ingested_events_total 0" in body
    assert "zylar_deduplicated_events_total 0" in body


def test_metrics_collector_thread_safety():
    collector = MetricsCollector()
    num_threads = 10
    increments_per_thread = 100

    def worker():
        for _ in range(increments_per_thread):
            collector.record_event_ingested(1)
            collector.record_event_deduplicated(1)
            collector.record_detection_rule_fired("RULE_PORT_SCAN_REJECT", 1)
            collector.record_workflow_execution("success", 0.01)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        for f in futures:
            f.result()

    text = collector.get_prometheus_text()
    expected_total = num_threads * increments_per_thread
    assert f"zylar_ingested_events_total {expected_total}" in text
    assert f"zylar_deduplicated_events_total {expected_total}" in text
    assert f'zylar_detection_rules_fired_total{{rule="RULE_PORT_SCAN_REJECT"}} {expected_total}' in text
    assert f'zylar_workflow_executions_total{{status="success"}} {expected_total}' in text
