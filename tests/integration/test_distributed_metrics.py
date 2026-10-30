"""Integration tests for distributed observability, metric ownership, and Prometheus exposition."""

from pathlib import Path

import yaml  # type: ignore[import-untyped]
from dashboard.app import parse_prometheus_metrics

from zylar.core.metrics import MetricsCollector


def test_metrics_counter_commit_boundary_semantics():
    """Counters must only increment upon successful transaction completion without high-cardinality labels."""
    collector = MetricsCollector()
    collector.record_workflow_events_completed(10)
    collector.record_incidents_persisted(1)
    collector.record_checkpoint_advance()

    out = collector.format_prometheus_exposition()
    assert "zylar_workflow_events_completed_total 10" in out
    assert "zylar_incidents_persisted_total 1" in out
    assert "zylar_ingestion_checkpoint_advances_total 1" in out
    # Ensure no raw event IDs or IP labels are exposed in Prometheus text
    assert "event_id=" not in out
    assert "source_ip=" not in out


def test_metrics_collector_format_exposition_alias():
    """format_prometheus_exposition and get_prometheus_text must return identical text."""
    collector = MetricsCollector()
    assert collector.format_prometheus_exposition() == collector.get_prometheus_text()


def test_dashboard_parse_prometheus_metrics_handles_commit_bounded_counters():
    """Dashboard metrics parser must extract commit-bounded counters from exposition text."""
    collector = MetricsCollector()
    collector.record_workflow_events_completed(42)
    collector.record_incidents_persisted(7)
    collector.record_checkpoint_advance(3)

    text = collector.format_prometheus_exposition()
    parsed = parse_prometheus_metrics(text)

    assert parsed["status"] == "available"
    assert parsed["workflow_events_completed"] == 42
    assert parsed["incidents_persisted"] == 7
    assert parsed["checkpoint_advances"] == 3


def test_prometheus_scrape_config_targets_api_and_worker():
    """Prometheus configuration must define dual scrape jobs for API and Worker."""
    prom_cfg_path = Path("docker/prometheus.yml")
    assert prom_cfg_path.exists(), "docker/prometheus.yml must exist"

    with open(prom_cfg_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    jobs = {j["job_name"]: j for j in cfg.get("scrape_configs", [])}
    assert "zylar-api" in jobs
    assert "zylar-worker" in jobs

    api_targets = jobs["zylar-api"]["static_configs"][0]["targets"]
    assert "api:8000" in api_targets

    worker_targets = jobs["zylar-worker"]["static_configs"][0]["targets"]
    assert "worker:9102" in worker_targets
