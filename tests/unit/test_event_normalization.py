from __future__ import annotations

from zylar.domain.events import EventNormalizer, NormalizedEvent


def test_normalize_elasticsearch_hit_with_source():
    hit = {
        "_index": "security-logs-2026",
        "_id": "es-doc-123",
        "_source": {
            "timestamp": "2026-10-25T15:00:00Z",
            "event_type": "authentication",
            "source_ip": "10.0.0.5",
            "user": "root",
            "status": "failed",
            "details": "Invalid password",
        },
    }

    event = EventNormalizer.normalize_single(hit)
    assert isinstance(event, NormalizedEvent)
    # Event ID resolved from ES _id scoped by index
    assert event.event_id == "security-logs-2026:es-doc-123"
    assert event.source == "security-logs-2026"
    assert event.source_ip == "10.0.0.5"
    assert event.user == "root"


def test_event_identity_precedence_tier1_stable_event_id():
    """Tier 1: Explicit event_id takes precedence over ES _id and documented fields."""
    raw = {
        "_index": "security-logs",
        "_id": "es-id-999",
        "_source": {
            "event_id": "explicit-stable-id-001",
            "source_event_id": "sub-id-123",
            "timestamp": "2026-10-25T15:00:00Z",
            "event_type": "authentication",
        },
    }
    event = EventNormalizer.normalize_single(raw)
    assert event.event_id == "explicit-stable-id-001"


def test_event_identity_precedence_tier2_elasticsearch_scoped_id():
    """Tier 2: ES _id scoped by index or source when event_id is absent."""
    raw = {
        "_index": "corp-audit",
        "_id": "doc-554433",
        "_source": {
            "source_event_id": "legacy-record-44",
            "timestamp": "2026-10-25T15:00:00Z",
            "event_type": "network",
        },
    }
    event = EventNormalizer.normalize_single(raw)
    assert event.event_id == "corp-audit:doc-554433"


def test_event_identity_precedence_tier3_deterministic_source_identity():
    """Tier 3: Documented source identity (source_event_id, record_id, id, log_id) produces idempotent ID."""
    raw1 = {
        "source_event_id": "evt-win-4624",
        "timestamp": "2026-10-25T15:00:00Z",
        "event_type": "auth",
        "user": "alice",
    }
    event1a = EventNormalizer.normalize_single(raw1, default_source="winevent")
    event1b = EventNormalizer.normalize_single(raw1, default_source="winevent")
    assert event1a.event_id == "winevent:evt-win-4624"
    assert event1a.event_id == event1b.event_id  # Idempotent across retries

    raw2 = {
        "record_id": 98765,
        "timestamp": "2026-10-25T15:00:00Z",
        "event_type": "firewall",
    }
    event2 = EventNormalizer.normalize_single(raw2, default_source="paloalto")
    assert event2.event_id == "paloalto:98765"


def test_event_identity_precedence_tier4_generated_uuid():
    """Tier 4: Generated UUID fallback when no stable identifier exists.

    Limitation: UUID generation cannot guarantee deduplication across retries.
    Content hash is NOT used as event_id so identical payloads do not collide.
    """
    raw = {
        "timestamp": "2026-10-25T15:00:00Z",
        "event_type": "raw_telemetry",
        "details": "heartbeat",
    }
    event_a = EventNormalizer.normalize_single(raw, default_source="sensor")
    event_b = EventNormalizer.normalize_single(raw, default_source="sensor")

    assert event_a.event_id.startswith("gen-")
    assert event_b.event_id.startswith("gen-")
    # Two separate normalization passes of identical payload without ID produce unique IDs
    assert event_a.event_id != event_b.event_id


def test_normalize_direct_dictionary_with_legacy_username():
    raw = {
        "event_id": "direct-001",
        "timestamp": "2026-10-25T16:00:00Z",
        "event_type": "network",
        "source_ip": "172.16.0.10",
        "username": "network_agent",
        "destination_port": 22,
        "status": "rejected",
    }

    event = EventNormalizer.normalize_single(raw, default_source="firewall")
    assert event.event_id == "direct-001"
    assert event.user == "network_agent"
    assert event.destination_port == 22
    assert event.source == "firewall"


def test_normalize_batch_segregation():
    batch = [
        # Valid event 1
        {
            "event_id": "valid-1",
            "timestamp": "2026-10-25T17:00:00Z",
            "event_type": "auth",
            "source_ip": "192.168.1.1",
            "user": "alice",
        },
        # Invalid event 1 (malformed IP)
        {
            "event_id": "invalid-1",
            "timestamp": "2026-10-25T17:01:00Z",
            "event_type": "auth",
            "source_ip": "999.999.999.999",
        },
        # Invalid event 2 (missing timestamp)
        {
            "event_id": "invalid-2",
            "event_type": "auth",
        },
        # Valid event 2
        {
            "event_id": "valid-2",
            "timestamp": "2026-10-25T17:02:00Z",
            "event_type": "network",
            "destination_port": 80,
        },
    ]

    result = EventNormalizer.normalize_batch(batch)
    assert result.total_processed == 4
    assert len(result.events) == 2
    assert len(result.quarantined) == 2

    assert result.events[0].event_id == "valid-1"
    assert result.events[1].event_id == "valid-2"

    assert result.quarantined[0]["batch_index"] == 1
    assert "Invalid IP address" in result.quarantined[0]["error_reason"]

    assert result.quarantined[1]["batch_index"] == 2
    assert (
        "Field required" in result.quarantined[1]["error_reason"]
        or "timestamp" in result.quarantined[1]["error_reason"]
    )
