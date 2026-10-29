from __future__ import annotations

import os
from typing import Any

from agents.state import AgentState
from zylar.analysis.risk_scoring import DEFAULT_RISK_POLICY, RiskPolicy, evaluate_risk
from zylar.persistence.database import get_session
from zylar.persistence.exceptions import DatabaseConnectionError
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


def calculate_risk_node(state: AgentState, policy: RiskPolicy | None = None) -> dict[str, Any]:
    """Calculates risk score based on multi-factor weighted heuristics and canonical inputs."""
    classification = state.get("attack_classification", "None")
    anomalies = state.get("anomalies", [])

    active_policy = policy or DEFAULT_RISK_POLICY

    if not anomalies or classification == "None":
        eval_result = evaluate_risk(dict(state), policy=active_policy)
        return {
            "risk_score": eval_result.risk_score,
            "risk_category": eval_result.risk_category,
            "risk_policy_version": eval_result.policy_version,
            "risk_breakdown": eval_result.breakdown,
            "historical_recurrence": 0,
            "asset_criticality": 50,
            "contributing_ips": [],
            "contributing_users": [],
        }

    # Extract contributing entities canonically
    ips = sorted(
        {str(a["source_ip"]) for a in anomalies if isinstance(a, dict) and a.get("source_ip")}
    )
    users = sorted(
        {
            str(a.get("user") or a.get("username"))
            for a in anomalies
            if isinstance(a, dict) and (a.get("user") or a.get("username"))
        }
    )

    # Replay idempotency guard: if incident was already evaluated/persisted for this idempotency key,
    # return recorded scores to prevent replay drift from newly accumulated entity recurrence.
    idempotency_key = state.get("idempotency_key")
    if idempotency_key:
        try:
            with get_session() as session:
                from zylar.persistence.repositories import IncidentRepository

                repo = IncidentRepository(session)
                existing = repo.get_by_idempotency_key(idempotency_key)
                if existing is not None and existing.attack_classification == classification:
                    existing_threat = (
                        existing.threat_intel if isinstance(existing.threat_intel, dict) else {}
                    )
                    policy_ver = str(
                        existing_threat.get("risk_policy_version", active_policy.policy_version)
                    )
                    breakdown = existing_threat.get("risk_breakdown")
                    if not isinstance(breakdown, dict):
                        breakdown = {
                            "volume": 0.0,
                            "severity": float(existing.risk_score),
                            "recurrence": 0.0,
                            "centrality": 0.0,
                            "criticality": 50.0,
                        }
                    return {
                        "risk_score": existing.risk_score,
                        "risk_category": existing.risk_category,
                        "risk_policy_version": policy_ver,
                        "risk_breakdown": breakdown,
                        "historical_recurrence": 0,
                        "asset_criticality": int(breakdown.get("criticality", 50)),
                        "contributing_ips": ips,
                        "contributing_users": users,
                    }
        except DatabaseConnectionError:
            raise
        except Exception:
            if os.environ.get("ZYLAR_REQUIRE_POSTGRES") == "1" or os.environ.get("CI") == "true":
                raise

    # Query historical recurrence factor from PostgreSQL
    historical_recurrence = get_historical_recurrence_factor(ips, users)

    # Delegate calculation to pure deterministic risk engine
    scoring_payload = dict(state)
    scoring_payload["historical_recurrence"] = historical_recurrence

    eval_result = evaluate_risk(scoring_payload, policy=active_policy)

    return {
        "risk_score": eval_result.risk_score,
        "risk_category": eval_result.risk_category,
        "risk_policy_version": eval_result.policy_version,
        "risk_breakdown": eval_result.breakdown,
        "historical_recurrence": historical_recurrence,
        "asset_criticality": int(eval_result.breakdown.get("criticality", 50)),
        "contributing_ips": ips,
        "contributing_users": users,
    }

