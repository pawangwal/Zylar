from __future__ import annotations

from typing import Any

from agents.state import AgentState
from zylar.persistence.database import get_session
from zylar.persistence.repositories import OffenderHistoryRepository


def get_historical_recurrence_factor(ips: list[str], users: list[str]) -> int:
    """Queries entity recurrence penalty factor (0-100) from PostgreSQL."""
    with get_session() as session:
        repo = OffenderHistoryRepository(session)
        return repo.get_recurrence_factor(ips, users)


def update_entity_history(ips: list[str], users: list[str], risk_score: int) -> None:
    """Deprecated compatibility stub.

    Entity recurrence updates are now transactionally coordinated within
    UnitOfWork.persist_incident_lifecycle to prevent double-counting.
    """
    pass


def calculate_risk_node(state: AgentState) -> dict[str, Any]:
    """Calculates risk score based on multi-factor weighted heuristics and canonical inputs."""
    classification = state.get("attack_classification", "None")
    anomalies = state.get("anomalies", [])

    if not anomalies or classification == "None":
        return {"risk_score": 0, "risk_category": "Low"}

    idempotency_key = state.get("idempotency_key")
    if idempotency_key:
        try:
            with get_session() as session:
                from zylar.persistence.repositories import IncidentRepository

                repo = IncidentRepository(session)
                existing = repo.get_by_idempotency_key(idempotency_key)
                if existing is not None and existing.attack_classification == classification:
                    return {
                        "risk_score": existing.risk_score,
                        "risk_category": existing.risk_category,
                        "historical_recurrence": 0,
                        "asset_criticality": 50,
                    }
        except Exception:
            pass

    # Factor 1: Attack Severity (0-100)
    severity_weight = 0
    if classification == "Ransomware":
        severity_weight = 100
    elif classification == "Brute Force":
        severity_weight = 60
    elif classification == "Port Scan":
        severity_weight = 30
    elif classification == "Suspicious IP Activity":
        severity_weight = 50
    elif classification == "DDoS":
        severity_weight = 90
    else:
        severity_weight = 40

    # Factor 2: Anomaly Confidence (0-100 proxy using volume)
    anomaly_confidence = min(100, len(anomalies) * 5)

    # Factor 3: Historical Recurrence (0-100 from PostgreSQL) using canonical entity identities
    ips = sorted({str(a["source_ip"]) for a in anomalies if a.get("source_ip")})
    users = sorted(
        {
            str(a.get("user") or a.get("username"))
            for a in anomalies
            if (a.get("user") or a.get("username"))
        }
    )
    historical_recurrence = get_historical_recurrence_factor(ips, users)

    # Factor 4: Graph Centrality (0-100 from state)
    graph_centrality = state.get("graph_centrality", 0.0)

    # Factor 5: Asset Criticality (0-100 heuristic based on validated destination ports)
    asset_criticality = 50  # Default baseline
    target_ports = {
        int(a["destination_port"]) for a in anomalies if a.get("destination_port") is not None
    }
    if 22 in target_ports or 3389 in target_ports:
        asset_criticality = 90  # High for SSH/RDP
    elif 443 in target_ports or 80 in target_ports:
        asset_criticality = 70

    # Weighted Formula
    risk_score = (
        (anomaly_confidence * 0.25)
        + (severity_weight * 0.25)
        + (historical_recurrence * 0.20)
        + (graph_centrality * 0.15)
        + (asset_criticality * 0.15)
    )

    final_score = int(min(100, risk_score))

    if final_score >= 80:
        category = "Critical"
    elif final_score >= 60:
        category = "High"
    elif final_score >= 40:
        category = "Medium"
    else:
        category = "Low"

    return {
        "risk_score": final_score,
        "risk_category": category,
        "historical_recurrence": historical_recurrence,
        "asset_criticality": asset_criticality,
        "contributing_ips": ips,
        "contributing_users": users,
    }
