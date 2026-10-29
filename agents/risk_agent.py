from __future__ import annotations

import logging
from typing import Any

from agents.report_agent import compute_canonical_batch_fingerprint, extract_or_compute_raw_hash
from agents.state import AgentState
from zylar.analysis.risk_scoring import DEFAULT_RISK_POLICY, RiskPolicy, evaluate_risk
from zylar.persistence.database import get_session
from zylar.persistence.repositories import OffenderHistoryRepository

logger = logging.getLogger("ZYLAR-RiskAgent")


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
    # validate canonical batch identity and policy version before reusing recorded scores to prevent drift.
    idempotency_key = state.get("idempotency_key")
    if idempotency_key:
        with get_session() as session:
            from zylar.persistence.exceptions import IdempotencyConflictError
            from zylar.persistence.repositories import IncidentRepository

            repo = IncidentRepository(session)
            existing = repo.get_by_idempotency_key(idempotency_key)
            if existing is not None:
                # 1. Validate classification match
                if existing.attack_classification != classification:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' conflicts with existing incident "
                        f"'{existing.incident_id}' (classification mismatch: "
                        f"'{existing.attack_classification}' vs '{classification}')"
                    )

                # 2. Validate anomaly event count match
                if existing.anomalous_events_count != len(anomalies):
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' conflicts with existing incident "
                        f"'{existing.incident_id}' (anomalous events count mismatch: "
                        f"{existing.anomalous_events_count} vs {len(anomalies)})"
                    )

                # 3. Validate canonical batch identity fingerprint
                existing_threat = (
                    existing.threat_intel if isinstance(existing.threat_intel, dict) else {}
                )
                incoming_fingerprint = compute_canonical_batch_fingerprint(anomalies)

                if "batch_fingerprint" in existing_threat:
                    recorded_fingerprint = str(existing_threat["batch_fingerprint"])
                    if recorded_fingerprint != incoming_fingerprint:
                        raise IdempotencyConflictError(
                            f"Idempotency key '{idempotency_key}' conflicts with existing incident "
                            f"'{existing.incident_id}' (canonical batch identity fingerprint mismatch: "
                            f"'{recorded_fingerprint}' vs '{incoming_fingerprint}')"
                        )
                elif existing.event_refs:
                    # Legacy fallback: compare event reference hashes when batch_fingerprint was not stored
                    existing_hashes = sorted(
                        ref.raw_event_hash for ref in existing.event_refs if ref.raw_event_hash
                    )
                    incoming_hashes = sorted(
                        extract_or_compute_raw_hash(a) for a in anomalies if isinstance(a, dict)
                    )
                    if existing_hashes and existing_hashes != incoming_hashes:
                        raise IdempotencyConflictError(
                            f"Idempotency key '{idempotency_key}' conflicts with existing incident "
                            f"'{existing.incident_id}' (event reference hashes mismatch)"
                        )
                else:
                    logger.warning(
                        "Replaying legacy incident '%s' lacking batch fingerprint and event refs; "
                        "canonical batch identity cannot be strictly verified",
                        existing.incident_id,
                    )

                # 4. Validate scoring policy version consistency if recorded
                if "risk_policy_version" in existing_threat:
                    recorded_policy_ver = str(existing_threat["risk_policy_version"])
                    if recorded_policy_ver != active_policy.policy_version:
                        raise IdempotencyConflictError(
                            f"Idempotency key '{idempotency_key}' conflicts with existing incident "
                            f"'{existing.incident_id}' (scoring policy version mismatch: "
                            f"'{recorded_policy_ver}' vs '{active_policy.policy_version}')"
                        )
                    policy_ver = recorded_policy_ver
                else:
                    # Legacy incident lacks recorded policy version: mark as unknown rather than fabricating a match
                    policy_ver = "unknown-legacy-policy"

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

