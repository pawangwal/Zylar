from __future__ import annotations

from typing import Any, Dict
from agents.state import AgentState
from zylar.domain.events import EventNormalizer


def analyze_logs_node(state: AgentState) -> Dict[str, Any]:
    """Normalizes raw logs at the ingestion boundary using canonical domain validation."""
    raw_logs = state.get("raw_logs", [])
    if not raw_logs:
        return {"parsed_events": [], "quarantined_events": []}

    result = EventNormalizer.normalize_batch(raw_logs)

    # Serialize to JSON-compatible dictionaries for downstream compatibility
    parsed_events = [e.model_dump(mode="json") for e in result.events]

    return {
        "parsed_events": parsed_events,
        "quarantined_events": result.quarantined,
    }
