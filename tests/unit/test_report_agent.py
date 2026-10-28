from __future__ import annotations

from datetime import UTC, datetime

import pytest
from agents.report_agent import (
    compute_canonical_event_signature,
    derive_event_reference_id,
    extract_event_source,
    extract_or_compute_raw_hash,
    parse_event_timestamp,
)


def test_parse_event_timestamp_valid_iso_with_z():
    ts_str = "2026-10-28T12:30:45.123456Z"
    dt = parse_event_timestamp(ts_str, event_id="evt-1")
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 28
    assert dt.hour == 12
    assert dt.tzinfo == UTC


def test_parse_event_timestamp_valid_iso_with_offset():
    ts_str = "2026-10-28T14:30:45+02:00"
    dt = parse_event_timestamp(ts_str, event_id="evt-2")
    assert dt.tzinfo is not None
    # Converted to UTC
    assert dt.hour == 12
    assert dt.tzinfo == UTC


def test_parse_event_timestamp_naive_string_assumes_utc():
    ts_str = "2026-10-28T12:00:00"
    dt = parse_event_timestamp(ts_str, event_id="evt-3")
    assert dt.year == 2026
    assert dt.hour == 12
    assert dt.tzinfo == UTC


def test_parse_event_timestamp_datetime_object():
    now = datetime(2026, 10, 28, 10, 0, 0, tzinfo=UTC)
    dt = parse_event_timestamp(now, event_id="evt-4")
    assert dt == now
    assert dt.tzinfo == UTC


def test_parse_event_timestamp_missing_or_none_raises_value_error():
    """Confirms that genuinely missing timestamps raise ValueError and are not silently replaced with now_utc."""
    with pytest.raises(ValueError, match="missing or empty"):
        parse_event_timestamp(None, event_id="evt-bad-1")

    with pytest.raises(ValueError, match="missing or empty"):
        parse_event_timestamp("", event_id="evt-bad-2")

    with pytest.raises(ValueError, match="missing or empty"):
        parse_event_timestamp("   ", event_id="evt-bad-3")


def test_parse_event_timestamp_malformed_string_raises_value_error():
    """Confirms that malformed timestamps raise ValueError and cannot silently become current-time evidence."""
    with pytest.raises(ValueError, match="Malformed event timestamp"):
        parse_event_timestamp("not-a-valid-timestamp", event_id="evt-bad-4")

    with pytest.raises(ValueError, match="Malformed event timestamp"):
        parse_event_timestamp("2026-99-99T99:99:99", event_id="evt-bad-5")


def test_extract_event_source_precedence():
    # 1. 'source' present
    assert extract_event_source({"source": "suricata", "event_type": "zeek"}) == "suricata"
    # 2. 'source' absent, 'event_type' present
    assert extract_event_source({"event_type": "zeek"}) == "zeek"
    # 3. both absent -> fallback
    assert extract_event_source({}) == "soc_pipeline"


def test_derive_event_reference_id_stable_with_event_id():
    log = {"event_id": "upstream-evt-123", "source": "zeek"}
    ref_id = derive_event_reference_id(log, event_src="zeek", raw_hash="abc" * 21 + "a")
    assert ref_id == "upstream-evt-123"


def test_derive_event_reference_id_stable_with_es_doc_id():
    log = {"_id": "es-doc-999", "source": "zeek"}
    ref_id = derive_event_reference_id(log, event_src="zeek", raw_hash="abc" * 21 + "a")
    assert ref_id == "es-doc-999"


def test_derive_event_reference_id_stable_without_event_id_uses_raw_hash():
    """When event_id is absent, derive_event_reference_id uses raw_event_hash deterministically."""
    log1 = {"source": "zeek", "message": "Connection attempt", "ip": "10.0.0.1"}
    raw_hash1 = extract_or_compute_raw_hash(log1)
    ref_id1 = derive_event_reference_id(log1, event_src="zeek", raw_hash=raw_hash1)

    # Identical event payload in second run/replay
    log2 = {"source": "zeek", "message": "Connection attempt", "ip": "10.0.0.1"}
    raw_hash2 = extract_or_compute_raw_hash(log2)
    ref_id2 = derive_event_reference_id(log2, event_src="zeek", raw_hash=raw_hash2)

    assert raw_hash1 == raw_hash2
    assert ref_id1 == ref_id2
    assert ref_id1.startswith("evt-zeek-")
    assert not ref_id1.startswith("unstable-")


def test_derive_event_reference_id_unstable_fallback_when_no_data():
    """If no source, hash, or content exists, documents unstable fallback."""
    ref_id = derive_event_reference_id({}, event_src="soc_pipeline", raw_hash="")
    assert ref_id.startswith("unstable-")


def test_compute_canonical_event_signature_is_deterministic():
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    sig1 = compute_canonical_event_signature(
        event_src="zeek",
        source_event_id="evt-1",
        raw_hash="hash-1",
        event_ts=now,
        source_ip="192.168.1.50",
        destination_port=443,
        user_identifier="alice",
    )

    sig2 = compute_canonical_event_signature(
        event_src="zeek",
        source_event_id="evt-1",
        raw_hash="hash-1",
        event_ts=now,
        source_ip="192.168.1.50",
        destination_port=443,
        user_identifier="alice",
    )

    assert sig1 == sig2
    assert "zeek" in sig1
    assert "alice" in sig1
