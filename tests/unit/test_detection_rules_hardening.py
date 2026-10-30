from __future__ import annotations

from datetime import UTC, datetime

from zylar.analysis.correlation_service import build_correlation_graph
from zylar.analysis.detection_rules import evaluate_detection_rules


def test_single_locked_file_triggers_indicator_not_mass_encryption():
    """A single event with .locked extension triggers indicator rule, not mass encryption."""
    single_event = [
        {
            "event_id": "ev-1",
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "file_modification",
            "details": "User renamed file to important_doc.locked",
            "source_ip": "10.0.0.5",
            "user": "victim_alice",
        }
    ]
    res = evaluate_detection_rules(single_event)
    rule_ids = [m.rule_id for m in res.rule_matches]
    assert "RULE_RANSOMWARE_INDICATOR" in rule_ids
    assert "RULE_RANSOMWARE_MASS_ENCRYPTION" not in rule_ids


def test_mass_encryption_requires_twenty_events_in_sliding_window_per_entity():
    """Mass encryption rule requires >= 20 file encryption events within sliding window for same entity."""
    events = [
        {
            "event_id": f"ev-{i}",
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "file_encryption",
            "details": f"File {i} encrypted with key",
            "source_ip": "10.0.0.5",
            "user": "victim_alice",
        }
        for i in range(20)
    ]
    res = evaluate_detection_rules(events, window_seconds=300)
    rule_ids = [m.rule_id for m in res.rule_matches]
    assert "RULE_RANSOMWARE_MASS_ENCRYPTION" in rule_ids


def test_correlation_graph_bounds_entity_strings_with_hash_suffix():
    """Excessively long entity strings must be safely bounded to 128 chars while preserving uniqueness."""
    long_user = "x" * 200
    events = [
        {
            "source_ip": "192.168.1.100",
            "user": long_user,
            "destination_port": 22,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    ]
    graph_res = build_correlation_graph(events)
    user_entities = [e for e in graph_res.top_entities if e.startswith("User:")]
    assert len(user_entities) > 0
    entity = user_entities[0]
    assert len(entity) <= 128
    assert "_" in entity  # includes hash suffix
