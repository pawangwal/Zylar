"""Thread-safe Prometheus metrics accumulator and exposition formatter for Zylar."""

from __future__ import annotations

import threading
from collections import defaultdict


class MetricsCollector:
    """Thread-safe in-memory metric accumulator for Prometheus exposition."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ingested_events: int = 0
        self._deduplicated_events: int = 0
        self._workflow_counts: dict[str, int] = defaultdict(int)
        self._workflow_durations: dict[str, float] = defaultdict(float)
        self._rules_fired: dict[str, int] = defaultdict(int)

    def record_event_ingested(self, count: int = 1) -> None:
        """Records receipt of normalized events."""
        with self._lock:
            self._ingested_events += count

    def record_event_deduplicated(self, count: int = 1) -> None:
        """Records filtering of duplicated event signatures."""
        with self._lock:
            self._deduplicated_events += count

    def record_workflow_execution(self, status: str, duration_seconds: float) -> None:
        """Records execution outcome and runtime duration in seconds."""
        with self._lock:
            self._workflow_counts[status] += 1
            self._workflow_durations[status] += duration_seconds

    def record_detection_rule_fired(self, rule_id: str, count: int = 1) -> None:
        """Records trigger count for a deterministic SOC detection rule."""
        with self._lock:
            self._rules_fired[rule_id] += count

    def reset(self) -> None:
        """Resets all metrics to initial empty state (for tests and lifecycle teardown)."""
        with self._lock:
            self._ingested_events = 0
            self._deduplicated_events = 0
            self._workflow_counts.clear()
            self._workflow_durations.clear()
            self._rules_fired.clear()

    def get_prometheus_text(self) -> str:
        """Formats accumulated metrics in Prometheus exposition text format (v0.0.4)."""
        with self._lock:
            lines = [
                "# HELP zylar_ingested_events_total Total number of normalized events received.",
                "# TYPE zylar_ingested_events_total counter",
                f"zylar_ingested_events_total {self._ingested_events}",
                "# HELP zylar_deduplicated_events_total Total number of duplicate events filtered.",
                "# TYPE zylar_deduplicated_events_total counter",
                f"zylar_deduplicated_events_total {self._deduplicated_events}",
                "# HELP zylar_workflow_executions_total Executions by completion status.",
                "# TYPE zylar_workflow_executions_total counter",
            ]
            for st, cnt in sorted(self._workflow_counts.items()):
                lines.append(f'zylar_workflow_executions_total{{status="{st}"}} {cnt}')

            lines.extend([
                "# HELP zylar_workflow_execution_duration_seconds Total execution time in seconds by status.",
                "# TYPE zylar_workflow_execution_duration_seconds counter",
            ])
            for st, dur in sorted(self._workflow_durations.items()):
                lines.append(f'zylar_workflow_execution_duration_seconds{{status="{st}"}} {dur:.4f}')

            lines.extend([
                "# HELP zylar_detection_rules_fired_total Detections grouped by rule identifier.",
                "# TYPE zylar_detection_rules_fired_total counter",
            ])
            for r, cnt in sorted(self._rules_fired.items()):
                lines.append(f'zylar_detection_rules_fired_total{{rule="{r}"}} {cnt}')

            return "\n".join(lines) + "\n"


_collector: MetricsCollector | None = None
_init_lock = threading.Lock()


def get_metrics_collector() -> MetricsCollector:
    """Returns the singleton MetricsCollector instance."""
    global _collector
    if _collector is None:
        with _init_lock:
            if _collector is None:
                _collector = MetricsCollector()
    return _collector
