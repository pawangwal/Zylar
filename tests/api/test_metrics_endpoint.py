"""Tests for Prometheus operational metrics exposition endpoint, accumulator, and histogram validation."""

from __future__ import annotations

import concurrent.futures

import pytest
from api.main import app
from fastapi.testclient import TestClient

from zylar.core.metrics import (
    MetricsCollector,
    get_metrics_collector,
    validate_histogram_buckets,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_collector():
    collector = get_metrics_collector()
    collector.reset()
    yield
    collector.reset()


def test_metrics_endpoint_returns_prometheus_format():
    collector = get_metrics_collector()
    collector.record_events_received(42)
    collector.record_events_processed(35)
    collector.record_events_deduplicated(5)
    collector.record_events_quarantined(2)
    collector.record_detection_rule_fired("RULE_BRUTE_FORCE_AUTH", count=3)
    collector.record_workflow_execution(status="success", duration_seconds=0.125)

    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    assert "version=0.0.4" in res.headers["content-type"]

    body = res.text
    assert "# HELP zylar_events_received_total" in body
    assert "zylar_events_received_total 42" in body
    assert "# HELP zylar_events_processed_total" in body
    assert "zylar_events_processed_total 35" in body
    assert "# HELP zylar_events_deduplicated_total" in body
    assert "zylar_events_deduplicated_total 5" in body
    assert "# HELP zylar_events_quarantined_total" in body
    assert "zylar_events_quarantined_total 2" in body

    # Compatibility aliases
    assert "zylar_ingested_events_total 42" in body
    assert "zylar_deduplicated_events_total 5" in body

    assert 'zylar_detection_rules_fired_total{rule="RULE_BRUTE_FORCE_AUTH"} 3' in body
    assert 'zylar_workflow_executions_total{status="success"} 1' in body
    assert body.endswith("\n")


def test_metrics_endpoint_initial_empty_exposition():
    res = client.get("/metrics")
    assert res.status_code == 200
    body = res.text
    assert "zylar_events_received_total 0" in body
    assert "zylar_events_processed_total 0" in body
    assert "zylar_events_deduplicated_total 0" in body
    assert "zylar_events_quarantined_total 0" in body
    assert "zylar_ingested_events_total 0" in body
    assert "zylar_deduplicated_events_total 0" in body


def test_metrics_collector_thread_safety():
    collector = MetricsCollector()
    num_threads = 10
    increments_per_thread = 100

    def worker():
        for _ in range(increments_per_thread):
            collector.record_events_received(1)
            collector.record_events_processed(1)
            collector.record_events_deduplicated(1)
            collector.record_events_quarantined(1)
            collector.record_detection_rule_fired("RULE_PORT_SCAN_REJECT", 1)
            collector.record_workflow_execution("success", 0.01)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        for f in futures:
            f.result()

    text = collector.get_prometheus_text()
    expected_total = num_threads * increments_per_thread
    assert f"zylar_events_received_total {expected_total}" in text
    assert f"zylar_events_processed_total {expected_total}" in text
    assert f"zylar_events_deduplicated_total {expected_total}" in text
    assert f"zylar_events_quarantined_total {expected_total}" in text
    assert f'zylar_detection_rules_fired_total{{rule="RULE_PORT_SCAN_REJECT"}} {expected_total}' in text
    assert f'zylar_workflow_executions_total{{status="success"}} {expected_total}' in text


def test_metrics_histogram_and_duration_exposition():
    collector = get_metrics_collector()
    collector.record_workflow_execution("success", 0.05)
    collector.record_workflow_execution("success", 0.20)
    collector.record_workflow_execution("failed", 1.50)

    res = client.get("/metrics")
    assert res.status_code == 200
    body = res.text

    assert "# TYPE zylar_workflow_execution_duration_seconds histogram" in body
    assert 'zylar_workflow_execution_duration_seconds_bucket{le="0.05",status="success"} 1' in body
    assert 'zylar_workflow_execution_duration_seconds_bucket{le="0.25",status="success"} 2' in body
    assert 'zylar_workflow_execution_duration_seconds_bucket{le="+Inf",status="success"} 2' in body
    assert 'zylar_workflow_execution_duration_seconds_count{status="success"} 2' in body
    assert 'zylar_workflow_execution_duration_seconds_count{status="failed"} 1' in body
    assert 'zylar_workflow_execution_duration_seconds_total{status="success"} 0.2500' in body


def test_metrics_label_escaping():
    collector = get_metrics_collector()
    # Inject hostile/special characters into labels
    collector.record_detection_rule_fired('RULE"WITH"QUOTES\\AND\nNEWLINE', count=2)
    collector.record_workflow_execution('failed', 0.1)

    text = collector.get_prometheus_text()
    assert 'zylar_detection_rules_fired_total{rule="RULE\\"WITH\\"QUOTES\\\\AND\\nNEWLINE"} 2' in text
    assert 'zylar_workflow_executions_total{status="failed"} 1' in text


def test_metrics_histogram_bucket_validation():
    # Valid explicit buckets with terminal inf
    valid = validate_histogram_buckets([0.1, 0.5, 1.0, float("inf")])
    assert valid == (0.1, 0.5, 1.0, float("inf"))

    # Auto-appends inf if omitted
    auto_inf = validate_histogram_buckets([0.1, 0.5, 1.0])
    assert auto_inf == (0.1, 0.5, 1.0, float("inf"))

    # Empty buckets
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_histogram_buckets([])

    # Non-increasing buckets
    with pytest.raises(ValueError, match="strictly increasing"):
        validate_histogram_buckets([0.5, 0.2])

    # Equal adjacent buckets
    with pytest.raises(ValueError, match="strictly increasing"):
        validate_histogram_buckets([0.5, 0.5])

    # Non-positive bucket
    with pytest.raises(ValueError, match="strictly positive"):
        validate_histogram_buckets([-0.1, 1.0])
    with pytest.raises(ValueError, match="strictly positive"):
        validate_histogram_buckets([0.0, 1.0])

    # NaN bucket
    with pytest.raises(ValueError, match="cannot be NaN"):
        validate_histogram_buckets([0.1, float("nan"), 1.0])

    # Infinity not at end
    with pytest.raises(ValueError, match="terminal bucket"):
        validate_histogram_buckets([0.1, float("inf"), 1.0])


def test_metrics_workflow_execution_validation():
    collector = get_metrics_collector()

    # Disallowed status
    with pytest.raises(ValueError, match="Invalid workflow status"):
        collector.record_workflow_execution("unknown_status", 0.5)

    # Negative duration
    with pytest.raises(ValueError, match="non-negative finite float"):
        collector.record_workflow_execution("success", -0.01)

    # NaN duration
    with pytest.raises(ValueError, match="non-negative finite float"):
        collector.record_workflow_execution("success", float("nan"))

    # Infinite duration
    with pytest.raises(ValueError, match="non-negative finite float"):
        collector.record_workflow_execution("success", float("inf"))

    # Non-numeric duration
    with pytest.raises(TypeError, match="must be numeric"):
        collector.record_workflow_execution("success", "fast")  # type: ignore[arg-type]
