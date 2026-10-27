from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest
from pydantic import ValidationError

from zylar.domain.events import NormalizedEvent, compute_raw_event_hash
from zylar.domain.workflow import WorkflowRequest
from zylar.domain.responses import IncidentResponse, HealthResponse, ErrorResponse


def test_valid_normalized_event():
    event = NormalizedEvent(
        event_id="evt-001",
        timestamp="2026-10-25T14:30:00Z",
        event_type="authentication",
        source_ip="192.168.1.50",
        user="analyst_alice",
        status="success",
        destination_port=443,
        details="User logged in from corporate network",
        source="pam_auth",
    )

    assert event.event_id == "evt-001"
    assert event.timestamp == datetime(2026, 10, 25, 14, 30, 0, tzinfo=timezone.utc)
    assert event.event_type == "authentication"
    assert event.source_ip == "192.168.1.50"
    assert event.user == "analyst_alice"
    assert event.destination_port == 443
    assert len(event.raw_event_hash) == 64


def test_timestamp_with_offset_normalizes_to_utc():
    # +02:00 offset: 14:00 at +02:00 is 12:00 UTC
    event = NormalizedEvent(
        event_id="evt-002",
        timestamp="2026-10-25T14:00:00+02:00",
        event_type="web_access",
        source="nginx",
    )
    assert event.timestamp == datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


def test_timestamp_naive_string_rejected():
    with pytest.raises(ValidationError) as exc:
        NormalizedEvent(
            event_id="evt-003",
            timestamp="2026-10-25T14:00:00",  # Missing timezone
            event_type="web_access",
        )
    assert "timezone-aware" in str(exc.value)


def test_timestamp_naive_datetime_rejected():
    naive_dt = datetime(2026, 10, 25, 14, 0, 0)
    with pytest.raises(ValidationError) as exc:
        NormalizedEvent(
            event_id="evt-004",
            timestamp=naive_dt,
            event_type="web_access",
        )
    assert "timezone-aware" in str(exc.value)


def test_timestamp_malformed_string_rejected():
    with pytest.raises(ValidationError) as exc:
        NormalizedEvent(
            event_id="evt-005",
            timestamp="not-a-timestamp",
            event_type="web_access",
        )
    assert "Malformed ISO timestamp" in str(exc.value)


def test_empty_or_whitespace_event_id_rejected():
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id="   ",
            timestamp="2026-10-25T14:00:00Z",
            event_type="web_access",
        )


def test_valid_ipv6_accepted():
    event = NormalizedEvent(
        event_id="evt-006",
        timestamp="2026-10-25T14:00:00Z",
        event_type="network",
        source_ip="2001:db8::1",
    )
    assert event.source_ip == "2001:db8::1"


def test_invalid_ip_rejected():
    with pytest.raises(ValidationError) as exc:
        NormalizedEvent(
            event_id="evt-007",
            timestamp="2026-10-25T14:00:00Z",
            event_type="network",
            source_ip="999.1.2.3",
        )
    assert "Invalid IP address" in str(exc.value)


def test_destination_port_boundaries():
    # Boundary 1
    ev1 = NormalizedEvent(
        event_id="p-1",
        timestamp="2026-10-25T14:00:00Z",
        event_type="network",
        destination_port=1,
    )
    assert ev1.destination_port == 1

    # Boundary 65535
    ev_max = NormalizedEvent(
        event_id="p-max",
        timestamp="2026-10-25T14:00:00Z",
        event_type="network",
        destination_port=65535,
    )
    assert ev_max.destination_port == 65535

    # Out of bounds: 0
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id="p-0",
            timestamp="2026-10-25T14:00:00Z",
            event_type="network",
            destination_port=0,
        )

    # Out of bounds: 65536
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id="p-65536",
            timestamp="2026-10-25T14:00:00Z",
            event_type="network",
            destination_port=65536,
        )

    # Boolean not allowed as port
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id="p-bool",
            timestamp="2026-10-25T14:00:00Z",
            event_type="network",
            destination_port=True,  # type: ignore[arg-type]
        )


def test_legacy_username_compatibility_mapping():
    # Provide username instead of user in raw payload dict
    raw = {
        "event_id": "evt-legacy",
        "timestamp": "2026-10-25T14:00:00Z",
        "event_type": "auth",
        "username": "legacy_admin",
    }
    event = NormalizedEvent.model_validate(raw)
    assert event.user == "legacy_admin"


def test_raw_event_hash_deterministic():
    data = {"ip": "1.2.3.4", "action": "login"}
    h1 = compute_raw_event_hash(data)
    h2 = compute_raw_event_hash(data)
    assert h1 == h2
    assert len(h1) == 64


def test_workflow_request_duplicate_event_id_policy():
    ev1 = NormalizedEvent(
        event_id="dup-01",
        timestamp="2026-10-25T14:00:00Z",
        event_type="network",
    )
    ev2 = NormalizedEvent(
        event_id="dup-01",
        timestamp="2026-10-25T14:01:00Z",
        event_type="network",
    )

    # Default policy: reject duplicates
    with pytest.raises(ValidationError) as exc:
        WorkflowRequest(events=[ev1, ev2])
    assert "Duplicate event IDs found" in str(exc.value)

    # Explicit policy toggle: allow duplicates
    req = WorkflowRequest(events=[ev1, ev2], allow_duplicate_ids=True)
    assert len(req.events) == 2


def test_response_models():
    incident = IncidentResponse(
        incident_id="inc-100",
        attack_classification="Port Scan",
        risk_score=75,
        risk_category="High",
        mitigation_plan=["Block IP on perimeter firewall"],
    )
    assert incident.risk_score == 75

    health = HealthResponse(status="healthy")
    assert health.timestamp.tzinfo is not None

    err = ErrorResponse(error="InvalidRequest", correlation_id="req-999")
    assert err.details is None
