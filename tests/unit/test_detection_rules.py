from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from zylar.analysis.detection_rules import (
    RULES_VERSION,
    DetectionResult,
    RuleMatch,
    evaluate_detection_rules,
)


def test_empty_events_returns_no_attack():
    res = evaluate_detection_rules([])
    assert isinstance(res, DetectionResult)
    assert res.is_attack is False
    assert res.classification == "None"
    assert res.rule_matches == []
    assert res.statistical_outliers_count == 0
    assert res.rules_version == RULES_VERSION


def test_rule_brute_force_detected_when_threshold_exceeded():
    now = datetime.now(UTC)
    events = [
        {
            "event_id": f"bf-{i}",
            "source_ip": "198.51.100.44",
            "user": "root",
            "destination_port": 22,
            "status": "failed",
            "event_type": "authentication",
            "timestamp": (now + timedelta(seconds=i * 2)).isoformat(),
        }
        for i in range(6)
    ]
    res = evaluate_detection_rules(events)
    assert res.is_attack is True
    assert res.classification == "Brute Force"
    assert any(rm.rule_id == "RULE_BRUTE_FORCE_AUTH" for rm in res.rule_matches)

    match = next(rm for rm in res.rule_matches if rm.rule_id == "RULE_BRUTE_FORCE_AUTH")
    assert match.confidence >= 0.8
    assert len(match.matched_event_ids) == 6
    assert match.indicators["attempt_count"] == 6
    assert match.indicators["source_ip"] == "198.51.100.44"
    assert match.indicators["user"] == "root"


def test_rule_brute_force_below_threshold_does_not_fire():
    now = datetime.now(UTC)
    # Only 3 failed attempts (threshold is 5)
    events = [
        {
            "event_id": f"bf-{i}",
            "source_ip": "198.51.100.44",
            "user": "root",
            "destination_port": 22,
            "status": "failed",
            "event_type": "authentication",
            "timestamp": (now + timedelta(seconds=i * 2)).isoformat(),
        }
        for i in range(3)
    ]
    res = evaluate_detection_rules(events)
    assert not any(rm.rule_id == "RULE_BRUTE_FORCE_AUTH" for rm in res.rule_matches)


def test_rule_port_scan_detected_on_multiple_ports():
    now = datetime.now(UTC)
    events = [
        {
            "event_id": f"ps-{port}",
            "source_ip": "203.0.113.88",
            "destination_port": port,
            "status": "rejected",
            "event_type": "network",
            "timestamp": (now + timedelta(seconds=idx)).isoformat(),
        }
        for idx, port in enumerate(range(1000, 1015))
    ]
    res = evaluate_detection_rules(events)
    assert res.is_attack is True
    assert res.classification == "Port Scan"
    assert any(rm.rule_id == "RULE_PORT_SCAN_REJECT" for rm in res.rule_matches)

    match = next(rm for rm in res.rule_matches if rm.rule_id == "RULE_PORT_SCAN_REJECT")
    assert match.confidence >= 0.8
    assert match.indicators["unique_ports_count"] == 15
    assert match.indicators["source_ip"] == "203.0.113.88"


def test_rule_port_scan_below_threshold_does_not_fire():
    now = datetime.now(UTC)
    # Only 4 distinct ports (threshold is 10)
    events = [
        {
            "event_id": f"ps-{port}",
            "source_ip": "203.0.113.88",
            "destination_port": port,
            "status": "rejected",
            "event_type": "network",
            "timestamp": (now + timedelta(seconds=idx)).isoformat(),
        }
        for idx, port in enumerate(range(1000, 1004))
    ]
    res = evaluate_detection_rules(events)
    assert not any(rm.rule_id == "RULE_PORT_SCAN_REJECT" for rm in res.rule_matches)


def test_rule_ransomware_detected_on_file_indicators():
    now = datetime.now(UTC)
    events = [
        {
            "event_id": "rw-1",
            "source_ip": "10.0.0.50",
            "user": "victim_user",
            "event_type": "ransomware",
            "details": "Mass rename of 500 files to .locked extension",
            "timestamp": now.isoformat(),
        }
    ]
    res = evaluate_detection_rules(events)
    assert res.is_attack is True
    assert res.classification == "Ransomware"
    assert any(rm.rule_id == "RULE_RANSOMWARE_INDICATOR" for rm in res.rule_matches)

    match = next(rm for rm in res.rule_matches if rm.rule_id == "RULE_RANSOMWARE_INDICATOR")
    assert match.confidence >= 0.9
    assert "rw-1" in match.matched_event_ids


def test_rule_precedence_hierarchy():
    # If both Ransomware and Brute Force occur, Ransomware takes precedence in classification
    now = datetime.now(UTC)
    events = [
        {
            "event_id": f"bf-{i}",
            "source_ip": "198.51.100.44",
            "user": "root",
            "destination_port": 22,
            "status": "failed",
            "event_type": "authentication",
            "timestamp": now.isoformat(),
        }
        for i in range(6)
    ]
    events.append(
        {
            "event_id": "rw-1",
            "source_ip": "10.0.0.50",
            "details": "ransomware payload detected",
            "timestamp": now.isoformat(),
        }
    )
    res = evaluate_detection_rules(events)
    assert res.is_attack is True
    assert res.classification == "Ransomware"
    # Both rules should be present in rule_matches
    rule_ids = {rm.rule_id for rm in res.rule_matches}
    assert "RULE_RANSOMWARE_INDICATOR" in rule_ids
    assert "RULE_BRUTE_FORCE_AUTH" in rule_ids


def test_sliding_window_filtering():
    base_time = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
    # 3 attempts at 12:00, 3 attempts at 12:30 (outside 300 second window)
    events = [
        {
            "event_id": f"bf-early-{i}",
            "source_ip": "198.51.100.44",
            "user": "root",
            "status": "failed",
            "event_type": "authentication",
            "timestamp": (base_time + timedelta(seconds=i * 2)).isoformat(),
        }
        for i in range(3)
    ] + [
        {
            "event_id": f"bf-late-{i}",
            "source_ip": "198.51.100.44",
            "user": "root",
            "status": "failed",
            "event_type": "authentication",
            "timestamp": (base_time + timedelta(minutes=30, seconds=i * 2)).isoformat(),
        }
        for i in range(3)
    ]
    # With window_seconds=300 (5 mins), neither window has >= 5 attempts
    res = evaluate_detection_rules(events, window_seconds=300)
    assert not any(rm.rule_id == "RULE_BRUTE_FORCE_AUTH" for rm in res.rule_matches)


def test_detection_result_models_are_immutable():
    match = RuleMatch(
        rule_id="RULE_TEST",
        rule_name="Test Rule",
        confidence=0.99,
        matched_event_ids=["evt-1"],
        indicators={"count": 1},
    )
    with pytest.raises((TypeError, ValidationError)):
        match.confidence = 0.50  # type: ignore[misc]

    result = DetectionResult(
        is_attack=True,
        classification="Brute Force",
        rule_matches=[match],
        statistical_outliers_count=0,
    )
    with pytest.raises((TypeError, ValidationError)):
        result.classification = "None"  # type: ignore[misc]
