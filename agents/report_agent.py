from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from fpdf import FPDF, XPos, YPos

from agents.state import AgentState
from zylar.analysis.risk_scoring import parse_valid_port
from zylar.persistence.dtos import EventRefData, IncidentCreate
from zylar.persistence.unit_of_work import UnitOfWork

logger = logging.getLogger("ZYLAR-ReportAgent")

REPORTS_DIR = Path(os.path.join(os.path.dirname(__file__), "..", "reports")).resolve()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def log_incident(incident_data: dict[str, Any]) -> None:
    """Deprecated compatibility stub.

    Incidents are now persisted via UnitOfWork to PostgreSQL.
    """
    pass


def parse_event_timestamp(ts_val: Any, event_id: str | None = None) -> datetime.datetime:
    """Parses and validates event timestamp; strictly rejects malformed or missing timestamps.

    Never fabricates current time for missing or invalid historical event times.
    """
    if ts_val is None or (isinstance(ts_val, str) and not ts_val.strip()):
        context = f" for event '{event_id}'" if event_id else ""
        raise ValueError(
            f"Event timestamp is missing or empty{context}; cannot fabricate current time."
        )

    if isinstance(ts_val, str):
        s = ts_val.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
        except Exception as exc:
            context = f" for event '{event_id}'" if event_id else ""
            raise ValueError(f"Malformed event timestamp '{ts_val}'{context}: {exc}") from exc
    elif isinstance(ts_val, datetime.datetime):
        dt = ts_val
    else:
        context = f" for event '{event_id}'" if event_id else ""
        raise ValueError(f"Unsupported event timestamp type '{type(ts_val).__name__}'{context}")

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    return dt.astimezone(datetime.UTC)


def extract_event_source(event_data: dict[str, Any]) -> str:
    """Canonical precedence for event source: source -> event_type -> 'soc_pipeline'."""
    src = event_data.get("source") or event_data.get("event_type") or "soc_pipeline"
    return str(src).strip() or "soc_pipeline"


def extract_or_compute_raw_hash(event_data: dict[str, Any]) -> str:
    """Extracts valid 64-char hex hash or computes deterministic SHA-256 of canonical event fields."""
    raw_hash = event_data.get("raw_event_hash")
    if isinstance(raw_hash, str) and len(raw_hash.strip()) == 64:
        return raw_hash.strip().lower()
    hash_keys = sorted(k for k in event_data if k != "raw_event_hash")
    canonical_repr = "|".join(f"{k}:{event_data[k]}" for k in hash_keys)
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


def derive_event_reference_id(event_data: dict[str, Any], event_src: str, raw_hash: str) -> str:
    """Derives stable, deterministic reference ID following documented precedence:
    1. Stable upstream event ID (event_id or id)
    2. Documented Elasticsearch/source document ID (_id or doc_id)
    3. Deterministic identity derived from source and raw hash: f'evt-{event_src}-{raw_hash[:16]}'
    4. Explicit fallback only if no hash exists: f'unstable-{uuid.uuid4().hex[:12]}'
    """
    eid = event_data.get("event_id") or event_data.get("id")
    if eid and str(eid).strip():
        return str(eid).strip()

    doc_id = event_data.get("_id") or event_data.get("doc_id")
    if doc_id and str(doc_id).strip():
        return str(doc_id).strip()

    if raw_hash and len(raw_hash) >= 16:
        return f"evt-{event_src}-{raw_hash[:16]}"

    logger.warning("Event missing event_id, doc_id, and raw_hash; generating unstable fallback ID.")
    return f"unstable-{uuid.uuid4().hex[:12]}"


def compute_canonical_event_signature(
    event_src: str,
    source_event_id: str,
    raw_hash: str,
    event_ts: datetime.datetime,
    source_ip: str | None,
    destination_port: int | None,
    user_identifier: str | None,
) -> str:
    ts_str = event_ts.isoformat()
    sip = source_ip or ""
    dport = str(destination_port) if destination_port is not None else ""
    user = user_identifier or ""
    return f"{event_src}:{source_event_id}:{raw_hash}:{ts_str}:{sip}:{dport}:{user}"


def compute_canonical_batch_fingerprint(anomalies: list[dict[str, Any]] | None) -> str:
    """Computes a deterministic 64-char SHA-256 fingerprint representing the canonical identities
    of all constituent anomalies in a batch.
    """
    if not anomalies:
        return hashlib.sha256(b"empty_anomaly_batch").hexdigest()

    signatures: list[str] = []
    for a in anomalies:
        if not isinstance(a, dict):
            continue
        raw_hash = extract_or_compute_raw_hash(a)
        event_src = extract_event_source(a)
        source_event_id = derive_event_reference_id(a, event_src, raw_hash)
        ts_val = a.get("timestamp")
        if ts_val:
            try:
                event_ts = parse_event_timestamp(ts_val, event_id=source_event_id)
            except Exception:
                event_ts = datetime.datetime.fromtimestamp(0, tz=datetime.UTC)
        else:
            event_ts = datetime.datetime.fromtimestamp(0, tz=datetime.UTC)

        source_ip = str(a["source_ip"]).strip() if a.get("source_ip") else None
        dest_port = parse_valid_port(a.get("destination_port"))
        user_id = (
            str(a.get("user") or a.get("username")).strip()
            if (a.get("user") or a.get("username"))
            else None
        )
        sig = compute_canonical_event_signature(
            event_src=event_src,
            source_event_id=source_event_id,
            raw_hash=raw_hash,
            event_ts=event_ts,
            source_ip=source_ip,
            destination_port=dest_port,
            user_identifier=user_id,
        )
        signatures.append(sig)

    signatures.sort()
    return hashlib.sha256("||".join(signatures).encode("utf-8")).hexdigest()


def save_report_artifacts(
    report_content: dict[str, Any], mitigation_plan: list[str] | None = None
) -> None:
    """Saves JSON and PDF report artifacts to REPORTS_DIR without database coupling."""
    authoritative_id = report_content.get("incident_id", "UNKNOWN")
    timestamp_str = str(report_content.get("timestamp", ""))
    attack_classification = str(report_content.get("attack_classification", ""))
    risk_score = report_content.get("risk_score", 0)
    risk_category = str(report_content.get("risk_category", ""))
    steps = mitigation_plan or report_content.get("mitigation_plan") or []

    # 1. Save JSON report artifact
    try:
        json_path = REPORTS_DIR / f"{authoritative_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_content, f, indent=4)
    except Exception as exc:
        logger.warning("Failed to write JSON report artifact for %s: %s", authoritative_id, exc)

    # 2. Save PDF report artifact (failures do not compromise database state)
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=12)

        pdf.cell(
            200, 10, text="ZYLAR INCIDENT REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C"
        )
        pdf.cell(
            200,
            10,
            text=f"Incident ID: {authoritative_id}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="L",
        )
        pdf.cell(
            200, 10, text=f"Time: {timestamp_str}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L"
        )
        pdf.cell(
            200,
            10,
            text=f"Classification: {attack_classification}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="L",
        )
        pdf.cell(
            200,
            10,
            text=f"Risk: {risk_score} ({risk_category})",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="L",
        )

        pdf.cell(200, 10, text="Mitigation Plan:", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        for step in steps:
            pdf.cell(200, 10, text=f"- {step}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

        pdf_path = REPORTS_DIR / f"{authoritative_id}.pdf"
        pdf.output(str(pdf_path))
    except Exception as exc:
        logger.warning(
            "Failed to render PDF report artifact for %s: %s",
            authoritative_id,
            type(exc).__name__,
        )


def generate_report_node(state: AgentState) -> dict[str, Any]:
    """Generates the final incident report as JSON/PDF and optionally defers database persistence."""
    if state.get("attack_classification") == "None":
        return {"incident_id": "None", "report_content": {}}

    candidate_incident_id = f"ZYLAR-INC-{uuid.uuid4().hex[:8].upper()}"
    now_utc = datetime.datetime.now(datetime.UTC)

    # 1. Parse and extract constituent events canonically
    anomalies = state.get("anomalies") or []
    event_refs: list[EventRefData] = []
    canonical_signatures: list[str] = []

    for a in anomalies:
        raw_hash = extract_or_compute_raw_hash(a)
        event_src = extract_event_source(a)
        source_event_id = derive_event_reference_id(a, event_src, raw_hash)
        event_ts = parse_event_timestamp(a.get("timestamp"), event_id=source_event_id)
        source_ip = str(a["source_ip"]).strip() if a.get("source_ip") else None
        dest_port = parse_valid_port(a.get("destination_port"))
        user_id = (
            str(a.get("user") or a.get("username")).strip()
            if (a.get("user") or a.get("username"))
            else None
        )

        sig = compute_canonical_event_signature(
            event_src=event_src,
            source_event_id=source_event_id,
            raw_hash=raw_hash,
            event_ts=event_ts,
            source_ip=source_ip,
            destination_port=dest_port,
            user_identifier=user_id,
        )
        canonical_signatures.append(sig)

        event_refs.append(
            EventRefData(
                event_source=event_src,
                source_event_id=source_event_id,
                raw_event_hash=raw_hash,
                event_timestamp=event_ts,
                source_ip=source_ip,
                destination_port=dest_port,
                user_identifier=user_id,
            )
        )

    # 2. Establish stable idempotency key with deterministic identity semantics
    idempotency_key = state.get("idempotency_key")
    if not idempotency_key:
        if canonical_signatures:
            canonical_signatures.sort()
            sig_digest = hashlib.sha256(
                "||".join(canonical_signatures).encode("utf-8")
            ).hexdigest()[:24]
            classification = str(state.get("attack_classification") or "Unknown")
            idempotency_key = f"batch:{classification}:{sig_digest}"
        else:
            idempotency_key = f"unstable:no-events-{uuid.uuid4().hex[:12]}"
            logger.warning(
                "No upstream idempotency_key or constituent events found in state; "
                "replay deduplication is not guaranteed for key %s",
                idempotency_key,
            )

    # 3. Build validated DTO
    raw_threat = state.get("threat_intel")
    if isinstance(raw_threat, dict):
        threat_dict = dict(raw_threat)
    elif raw_threat is None:
        threat_dict = {}
    else:
        threat_dict = {"data": raw_threat}

    if "risk_policy_version" in state:
        threat_dict["risk_policy_version"] = str(state["risk_policy_version"])
    if "risk_breakdown" in state:
        bd = state["risk_breakdown"]
        threat_dict["risk_breakdown"] = dict(bd) if hasattr(bd, "items") else bd
    batch_fingerprint = compute_canonical_batch_fingerprint(anomalies)
    threat_dict["batch_fingerprint"] = batch_fingerprint

    incident_dto = IncidentCreate(
        incident_id=candidate_incident_id,
        idempotency_key=idempotency_key,
        timestamp=now_utc,
        attack_classification=str(state.get("attack_classification") or "Unknown"),
        risk_score=int(state.get("risk_score", 0)),
        risk_category=str(state.get("risk_category") or "Low"),
        mitigation_plan=list(state.get("mitigation_plan") or []),
        threat_intel=threat_dict,
        anomalous_events_count=len(state.get("anomalies", [])),
        status="NEW",
        event_refs=event_refs,
        actor=str(state.get("actor") or "zylar-pipeline"),
        correlation_id=str(state.get("correlation_id") or ""),
    )

    # If persistence is deferred (e.g. caller manages atomic boundary with checkpoint),
    # return the validated incident DTO without committing or opening UnitOfWork.
    if state.get("defer_persistence"):
        timestamp_str = incident_dto.timestamp.isoformat().replace("+00:00", "Z")
        raw_bd = threat_dict.get("risk_breakdown", {})
        report_content = {
            "incident_id": candidate_incident_id,
            "timestamp": timestamp_str,
            "attack_classification": incident_dto.attack_classification,
            "risk_category": incident_dto.risk_category,
            "risk_score": incident_dto.risk_score,
            "risk_policy_version": str(threat_dict.get("risk_policy_version", "risk-policy-v1")),
            "risk_breakdown": dict(raw_bd) if hasattr(raw_bd, "items") else raw_bd,
            "batch_fingerprint": batch_fingerprint,
            "threat_intel": incident_dto.threat_intel,
            "mitigation_plan": incident_dto.mitigation_plan,
            "anomalous_events_count": incident_dto.anomalous_events_count,
            "idempotency_key": idempotency_key,
        }
        return {
            "incident_id": candidate_incident_id,
            "report_content": report_content,
            "incident_dto": incident_dto,
            "contributing_ips": state.get("contributing_ips"),
            "contributing_users": state.get("contributing_users"),
        }

    # Immediate persistence path
    with UnitOfWork() as uow:
        result = uow.persist_incident_lifecycle(
            incident_dto,
            source_ips=state.get("contributing_ips"),
            user_identifiers=state.get("contributing_users"),
        )

    authoritative_id = result.incident.incident_id
    if not result.created:
        logger.info(
            "Replay detected for idempotency key '%s'; reusing existing incident '%s'",
            idempotency_key,
            authoritative_id,
        )

    timestamp_str = result.incident.timestamp.isoformat().replace("+00:00", "Z")
    persisted_threat = (
        result.incident.threat_intel if isinstance(result.incident.threat_intel, dict) else {}
    )

    persisted_bd = persisted_threat.get("risk_breakdown", state.get("risk_breakdown", {}))
    report_content = {
        "incident_id": authoritative_id,
        "timestamp": timestamp_str,
        "attack_classification": result.incident.attack_classification,
        "risk_category": result.incident.risk_category,
        "risk_score": result.incident.risk_score,
        "risk_policy_version": str(
            persisted_threat.get(
                "risk_policy_version", state.get("risk_policy_version", "risk-policy-v1")
            )
        ),
        "risk_breakdown": dict(persisted_bd) if hasattr(persisted_bd, "items") else persisted_bd,
        "batch_fingerprint": str(persisted_threat.get("batch_fingerprint", batch_fingerprint)),
        "threat_intel": result.incident.threat_intel,
        "mitigation_plan": result.incident.mitigation_plan,
        "anomalous_events_count": result.incident.anomalous_events_count,
        "idempotency_key": idempotency_key,
    }

    save_report_artifacts(report_content, result.incident.mitigation_plan)
    return {"incident_id": authoritative_id, "report_content": report_content}
