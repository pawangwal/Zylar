from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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
        """
        return (
            existing.attack_classification == self.attack_classification
            and existing.risk_score == self.risk_score
            and existing.risk_category == self.risk_category
            and existing.anomalous_events_count == self.anomalous_events_count
        )


@dataclass(frozen=True)
class PersistIncidentResult:
    """Outcome of an incident persistence operation."""

    incident: IncidentModel
    created: bool
    idempotency_key: str
