from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zylar.persistence.models import IncidentModel


@dataclass(frozen=True)
class EventRefData:
    """Constituent event metadata reference linking an incident to raw events in Elasticsearch."""

    event_source: str
    source_event_id: str
    raw_event_hash: str
    event_timestamp: datetime
    source_ip: str | None = None
    destination_port: int | None = None
    user_identifier: str | None = None


@dataclass
class IncidentCreate:
    """Input payload for creating or idempotently resolving an authoritative incident."""

    incident_id: str
    idempotency_key: str
    timestamp: datetime
    attack_classification: str
    risk_score: int
    risk_category: str
    mitigation_plan: list[str] = field(default_factory=list)
    threat_intel: dict[str, Any] = field(default_factory=dict)
    anomalous_events_count: int = 0
    status: str = "NEW"
    event_refs: list[EventRefData] = field(default_factory=list)
    actor: str = "zylar-pipeline"
    correlation_id: str = ""

    def matches_existing(self, existing: IncidentModel) -> bool:
        """Determines whether an existing incident matches this creation payload.

        Used to differentiate true idempotent replays from conflicting payload requests.
        Verifies classification, risk score, category, anomalous events count,
        mitigation plan, threat intelligence, and constituent event references.
        """
        if (
            existing.attack_classification != self.attack_classification
            or existing.risk_score != self.risk_score
            or existing.risk_category != self.risk_category
            or existing.anomalous_events_count != self.anomalous_events_count
            or (existing.mitigation_plan or []) != (self.mitigation_plan or [])
            or (existing.threat_intel or {}) != (self.threat_intel or {})
        ):
            return False

        def _ref_identity(
            r: Any,
        ) -> tuple[str, str, str, float, str | None, int | None, str | None]:
            ts = r.event_timestamp
            if ts.tzinfo is None:
                ts_epoch = ts.replace(tzinfo=UTC).timestamp()
            else:
                ts_epoch = ts.astimezone(UTC).timestamp()
            return (
                r.event_source,
                r.source_event_id,
                r.raw_event_hash,
                round(ts_epoch, 3),
                r.source_ip,
                r.destination_port,
                r.user_identifier,
            )

        existing_refs = sorted(_ref_identity(r) for r in (existing.event_refs or []))
        self_refs = sorted(_ref_identity(r) for r in (self.event_refs or []))
        return existing_refs == self_refs


@dataclass(frozen=True)
class PersistIncidentResult:
    """Outcome of an incident persistence operation."""

    incident: IncidentModel
    created: bool
    idempotency_key: str
