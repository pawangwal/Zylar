from __future__ import annotations

from typing import Any, TypedDict


class AgentState(TypedDict, total=False):
    # Log Layer
    raw_logs: list[dict[str, Any]]

    # Analyzer Layer
    parsed_events: list[dict[str, Any]]
    quarantined_events: list[dict[str, Any]]

    # Anomaly Layer
    anomalies: list[dict[str, Any]]

    # Threat Intelligence
    threat_intel: dict[str, Any]

    # Classification
    attack_classification: str

    # Correlation & History
    graph_centrality: float
    historical_recurrence: int
    asset_criticality: int
    contributing_ips: list[str]
    contributing_users: list[str]

    # Risk
    risk_score: int
    risk_category: str
    risk_policy_version: str
    risk_breakdown: dict[str, float]

    # Mitigation
    mitigation_plan: list[str]

    # Report & Persistence Lifecycle
    incident_id: str
    report_content: dict[str, Any]
    idempotency_key: str
    correlation_id: str
    actor: str
    defer_persistence: bool
    incident_dto: Any
