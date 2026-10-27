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
    # Event ID resolved from ES _id since _source had no event_id
    assert event.event_id == "es-doc-123"
    assert event.source == "security-logs-2026"
    assert event.source_ip == "10.0.0.5"
    assert event.user == "root"


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
    assert "Field required" in result.quarantined[1]["error_reason"] or "timestamp" in result.quarantined[1]["error_reason"]
