"""Thread-safe Prometheus metrics accumulator, latency histogram, and exposition formatter for Zylar.

Metric Lifecycle & Ownership Contract:
-------------------------------------------------------------------------------------------------------------------
Metric Name                                       Type       Responsible Component       Increment Point
-------------------------------------------------------------------------------------------------------------------
zylar_events_received_total                       Counter    CheckpointedIngestionWorker Batch fetch boundary from search
                                                             api/main.py /api/workflow   API workflow input boundary
zylar_events_processed_total                      Counter    CheckpointedIngestionWorker Durable transaction commit
                                                             api/main.py /api/workflow   Workflow completion
zylar_events_deduplicated_total                   Counter    CheckpointedIngestionWorker Watermark/cursor tie-breaker skip
                                                             OffenderHistoryRepository   Replay/duplicate event suppression
zylar_events_quarantined_total                    Counter    CheckpointedIngestionWorker Malformed/poison event quarantine
zylar_workflow_executions_total{status="..."}     Counter    CheckpointedIngestionWorker Autonomous workflow completion
                                                             api/main.py /api/workflow   API workflow completion
zylar_workflow_execution_duration_seconds_total   Counter    Workflow runner             Cumulative execution time (seconds)
zylar_workflow_execution_duration_seconds         Histogram  Workflow runner             Bucketed latency distribution (seconds)
zylar_detection_rules_fired_total{rule="..."}     Counter    Detection rules engine      Triggered deterministic rule
-------------------------------------------------------------------------------------------------------------------
Note on Multi-process Scope:
MetricsCollector stores metrics in-process memory with a threading.Lock. If Zylar is deployed
across multiple worker processes (e.g. gunicorn/uvicorn workers), each process maintains its own
counters. In production, configure Prometheus multiprocess mode or aggregate across scrape targets.
"""

from __future__ import annotations

import math
import threading
from collections import defaultdict
from collections.abc import Sequence

ALLOWED_WORKFLOW_STATUSES: frozenset[str] = frozenset({"success", "failed", "cancelled"})

DEFAULT_LATENCY_BUCKETS: tuple[float, ...] = (
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    float("inf"),
)


def validate_histogram_buckets(buckets: Sequence[float]) -> tuple[float, ...]:
    """Validates that histogram buckets are strictly increasing, positive, and end with +Inf."""
    if not buckets:
        raise ValueError("Histogram buckets sequence cannot be empty.")

    b_list = list(buckets)
    for idx, b in enumerate(b_list):
        if not isinstance(b, (int, float)):
            raise TypeError(f"Bucket boundary at index {idx} must be numeric, got {type(b).__name__}.")
        if math.isnan(b):
            raise ValueError(f"Bucket boundary at index {idx} cannot be NaN.")
        if b <= 0:
            raise ValueError(f"Bucket boundary at index {idx} must be strictly positive, got {b}.")
        if math.isinf(b) and idx != len(b_list) - 1:
            raise ValueError(f"Positive infinity can only appear as the terminal bucket (found at index {idx}).")

    for i in range(1, len(b_list)):
        if b_list[i] <= b_list[i - 1]:
            raise ValueError(
                f"Histogram buckets must be strictly increasing: bucket[{i-1}] ({b_list[i-1]}) "
                f">= bucket[{i}] ({b_list[i]})."
            )

    if not math.isinf(b_list[-1]):
        b_list.append(float("inf"))

    return tuple(b_list)


def escape_prometheus_label_value(val: str) -> str:
    """Escapes backslashes, double-quotes, and newlines per Prometheus text exposition format (v0.0.4)."""
    return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class MetricsCollector:
    """Thread-safe in-memory metric accumulator supporting lifecycle counters and latency histograms."""

    def __init__(self, buckets: Sequence[float] | None = None) -> None:
        self._lock = threading.Lock()
        self._buckets: tuple[float, ...] = (
            validate_histogram_buckets(buckets) if buckets is not None else DEFAULT_LATENCY_BUCKETS
        )
        self._events_received: int = 0
        self._events_processed: int = 0
        self._events_deduplicated: int = 0
        self._events_quarantined: int = 0

        self._workflow_counts: dict[str, int] = defaultdict(int)
        self._workflow_durations_sum: dict[str, float] = defaultdict(float)
        self._workflow_histogram_buckets: dict[str, dict[float, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._rules_fired: dict[str, int] = defaultdict(int)

    def record_events_received(self, count: int = 1) -> None:
        """Records receipt of events at ingestion poll or API input boundary."""
        if count <= 0:
            return
        with self._lock:
            self._events_received += count

    def record_events_processed(self, count: int = 1) -> None:
        """Records durable commit of events to PostgreSQL and advancement of checkpoint watermark.

        Note: Represents durable end-to-end incident processing success, which is distinct from
        workflow execution completion (inference/pipeline stage).
        """
        if count <= 0:
            return
        with self._lock:
            self._events_processed += count

    def record_events_deduplicated(self, count: int = 1) -> None:
        """Records duplicate/replay events filtered before processing."""
        if count <= 0:
            return
        with self._lock:
            self._events_deduplicated += count

    def record_events_quarantined(self, count: int = 1) -> None:
        """Records malformed/poison events diverted to dead-letter quarantine."""
        if count <= 0:
            return
        with self._lock:
            self._events_quarantined += count

    # Backward compatibility aliases
    def record_event_ingested(self, count: int = 1) -> None:
        """Deprecated alias for record_events_received."""
        self.record_events_received(count)

    def record_event_deduplicated(self, count: int = 1) -> None:
        """Deprecated alias for record_events_deduplicated."""
        self.record_events_deduplicated(count)

    def record_workflow_execution(self, status: str, duration_seconds: float) -> None:
        """Records LangGraph workflow execution outcome, cumulative runtime, and latency distribution buckets.

        Note: Indicates pipeline inference/detection completion, separate from durable database persistence.
        """
        clean_status = str(status).strip().lower()
        if clean_status not in ALLOWED_WORKFLOW_STATUSES:
            raise ValueError(
                f"Invalid workflow status '{status}'. Must be one of: {sorted(ALLOWED_WORKFLOW_STATUSES)}"
            )

        if not isinstance(duration_seconds, (int, float)):
            raise TypeError(f"duration_seconds must be numeric, got {type(duration_seconds).__name__}")
        if math.isnan(duration_seconds) or math.isinf(duration_seconds) or duration_seconds < 0.0:
            raise ValueError(
                f"duration_seconds must be a non-negative finite float, got {duration_seconds!r}"
            )

        safe_dur = float(duration_seconds)
        with self._lock:
            self._workflow_counts[clean_status] += 1
            self._workflow_durations_sum[clean_status] += safe_dur
            for b in self._buckets:
                if safe_dur <= b:
                    self._workflow_histogram_buckets[clean_status][b] += 1

    def record_detection_rule_fired(self, rule_id: str, count: int = 1) -> None:
        """Records trigger count for a deterministic SOC detection rule."""
        if count <= 0:
            return
        clean_rule = str(rule_id).strip() or "UNKNOWN_RULE"
        with self._lock:
            self._rules_fired[clean_rule] += count

    def reset(self) -> None:
        """Resets all metrics to initial empty state (for tests and lifecycle teardown)."""
        with self._lock:
            self._events_received = 0
            self._events_processed = 0
            self._events_deduplicated = 0
            self._events_quarantined = 0
            self._workflow_counts.clear()
            self._workflow_durations_sum.clear()
            self._workflow_histogram_buckets.clear()
            self._rules_fired.clear()

    def get_prometheus_text(self) -> str:
        """Formats accumulated metrics in standard Prometheus exposition text format (v0.0.4)."""
        with self._lock:
            lines = [
                "# HELP zylar_events_received_total Total number of events received at boundary.",
                "# TYPE zylar_events_received_total counter",
                f"zylar_events_received_total {self._events_received}",
                "# HELP zylar_events_processed_total Total number of events durably processed and committed to persistent store.",
                "# TYPE zylar_events_processed_total counter",
                f"zylar_events_processed_total {self._events_processed}",
                "# HELP zylar_events_deduplicated_total Total number of duplicate events filtered.",
                "# TYPE zylar_events_deduplicated_total counter",
                f"zylar_events_deduplicated_total {self._events_deduplicated}",
                "# HELP zylar_events_quarantined_total Total number of poison events quarantined in dead-letter store.",
                "# TYPE zylar_events_quarantined_total counter",
                f"zylar_events_quarantined_total {self._events_quarantined}",
                "# HELP zylar_ingested_events_total Deprecated compatibility alias for events received.",
                "# TYPE zylar_ingested_events_total counter",
                f"zylar_ingested_events_total {self._events_received}",
                "# HELP zylar_deduplicated_events_total Deprecated compatibility alias for events deduplicated.",
                "# TYPE zylar_deduplicated_events_total counter",
                f"zylar_deduplicated_events_total {self._events_deduplicated}",
                "# HELP zylar_workflow_executions_total Pipeline workflow executions by completion status (separate from durable DB persistence).",
                "# TYPE zylar_workflow_executions_total counter",
            ]
            for st, cnt in sorted(self._workflow_counts.items()):
                esc_st = escape_prometheus_label_value(st)
                lines.append(f'zylar_workflow_executions_total{{status="{esc_st}"}} {cnt}')

            lines.extend([
                "# HELP zylar_workflow_execution_duration_seconds_total Cumulative workflow execution duration in seconds by status.",
                "# TYPE zylar_workflow_execution_duration_seconds_total counter",
            ])
            for st, dur in sorted(self._workflow_durations_sum.items()):
                esc_st = escape_prometheus_label_value(st)
                lines.append(
                    f'zylar_workflow_execution_duration_seconds_total{{status="{esc_st}"}} {dur:.4f}'
                )

            lines.extend([
                "# HELP zylar_workflow_execution_duration_seconds Workflow execution latency in seconds distribution.",
                "# TYPE zylar_workflow_execution_duration_seconds histogram",
            ])
            all_statuses = sorted(
                set(self._workflow_counts.keys()).union(self._workflow_histogram_buckets.keys())
            )
            for st in all_statuses:
                esc_st = escape_prometheus_label_value(st)
                bucket_counts = self._workflow_histogram_buckets[st]
                for b in self._buckets:
                    b_str = "+Inf" if math.isinf(b) else f"{b:g}"
                    cnt = bucket_counts.get(b, 0)
                    lines.append(
                        f'zylar_workflow_execution_duration_seconds_bucket{{le="{b_str}",status="{esc_st}"}} {cnt}'
                    )
                sum_val = self._workflow_durations_sum.get(st, 0.0)
                tot_count = self._workflow_counts.get(st, 0)
                lines.append(
                    f'zylar_workflow_execution_duration_seconds_sum{{status="{esc_st}"}} {sum_val:.4f}'
                )
                lines.append(
                    f'zylar_workflow_execution_duration_seconds_count{{status="{esc_st}"}} {tot_count}'
                )

            lines.extend([
                "# HELP zylar_detection_rules_fired_total Detections grouped by rule identifier.",
                "# TYPE zylar_detection_rules_fired_total counter",
            ])
            for r, cnt in sorted(self._rules_fired.items()):
                esc_r = escape_prometheus_label_value(r)
                lines.append(f'zylar_detection_rules_fired_total{{rule="{esc_r}"}} {cnt}')

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
