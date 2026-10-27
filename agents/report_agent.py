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


def generate_report_node(state: AgentState) -> dict[str, Any]:
    """Generates the final incident report as JSON/PDF and atomically persists to PostgreSQL."""
    if state.get("attack_classification") == "None":
        return {"incident_id": "None", "report_content": {}}

    incident_id = f"ZYLAR-INC-{uuid.uuid4().hex[:8].upper()}"
    now_utc = datetime.datetime.now(datetime.UTC)
    timestamp_str = now_utc.isoformat().replace("+00:00", "Z")

    report_content = {
        "incident_id": incident_id,
        "timestamp": timestamp_str,
        "attack_classification": state.get("attack_classification"),
        "risk_category": state.get("risk_category"),
        "risk_score": state.get("risk_score"),
        "threat_intel": state.get("threat_intel"),
        "mitigation_plan": state.get("mitigation_plan"),
        "anomalous_events_count": len(state.get("anomalies", [])),
    }

    # Extract constituent event references
    seen_event_keys: set[tuple[str, str]] = set()
    event_refs: list[EventRefData] = []
    for a in state.get("anomalies", []):
        ts_raw = a.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                event_ts = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except Exception:
                event_ts = now_utc
        elif isinstance(ts_raw, datetime.datetime):
            event_ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=datetime.UTC)
        else:
            event_ts = now_utc

        source_event_id = str(a.get("event_id") or uuid.uuid4())
        event_src = str(a.get("event_type") or a.get("source") or "soc_pipeline")
        dedup_key = (event_src, source_event_id)
        if dedup_key in seen_event_keys:
            continue
        seen_event_keys.add(dedup_key)

        raw_hash = a.get("raw_event_hash")
        if not raw_hash or len(raw_hash) != 64:
            raw_hash = hashlib.sha256(source_event_id.encode()).hexdigest()

        event_refs.append(
            EventRefData(
                event_source=event_src,
                source_event_id=source_event_id,
                raw_event_hash=raw_hash,
                event_timestamp=event_ts,
                source_ip=str(a["source_ip"]) if a.get("source_ip") else None,
                destination_port=int(a["destination_port"]) if a.get("destination_port") is not None else None,
                user_identifier=str(a.get("user") or a.get("username")) if (a.get("user") or a.get("username")) else None,
            )
        )

    # Build DTO and persist incident lifecycle atomically
    idempotency_key = state.get("idempotency_key") or f"req:{incident_id}"
    raw_threat = state.get("threat_intel")
    if isinstance(raw_threat, dict):
        threat_dict = raw_threat
    elif raw_threat is None:
        threat_dict = {}
    else:
        threat_dict = {"data": raw_threat}

    incident_dto = IncidentCreate(
        incident_id=incident_id,
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

    with UnitOfWork() as uow:
        uow.persist_incident_lifecycle(
            incident_dto,
            source_ips=state.get("contributing_ips"),
            user_identifiers=state.get("contributing_users"),
        )

    # Save JSON report artifact
    json_path = REPORTS_DIR / f"{incident_id}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_content, f, indent=4)

    # Save PDF report artifact (failures do not compromise the committed database state)
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=12)

        pdf.cell(200, 10, text="ZYLAR INCIDENT REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.cell(200, 10, text=f"Incident ID: {incident_id}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        pdf.cell(200, 10, text=f"Time: {timestamp_str}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        pdf.cell(200, 10, text=f"Classification: {state.get('attack_classification')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        pdf.cell(200, 10, text=f"Risk: {state.get('risk_score')} ({state.get('risk_category')})", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

        pdf.cell(200, 10, text="Mitigation Plan:", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
        for step in state.get("mitigation_plan", []):
            pdf.cell(200, 10, text=f"- {step}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

        pdf_path = REPORTS_DIR / f"{incident_id}.pdf"
        pdf.output(str(pdf_path))
    except Exception as exc:
        logger.warning("Failed to render PDF report artifact for %s: %s", incident_id, exc)

    return {"incident_id": incident_id, "report_content": report_content}
