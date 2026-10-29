from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, ConfigDict

from zylar.analysis.risk_scoring import parse_valid_port

RULES_VERSION: str = "2026.10.1"


class RuleMatch(BaseModel):
    """Immutable representation of a deterministic detection rule match."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    confidence: float
    matched_event_ids: list[str]
    indicators: dict[str, Any]


class DetectionResult(BaseModel):
    """Immutable outcome of deterministic rule evaluation."""

    model_config = ConfigDict(frozen=True)

    is_attack: bool
    classification: str
    rule_matches: list[RuleMatch]
    statistical_outliers_count: int = 0
    rules_version: str = RULES_VERSION


def _parse_timestamp(ts_val: Any) -> datetime.datetime | None:
    """Safely parses timestamp into timezone-aware UTC datetime."""
    if ts_val is None:
        return None
    if isinstance(ts_val, datetime.datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=datetime.UTC)
        return ts_val.astimezone(datetime.UTC)
    if isinstance(ts_val, str):
        s = ts_val.strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.UTC)
            return dt.astimezone(datetime.UTC)
        except Exception:
            return None
    return None


def _find_windowed_events(
    events: list[tuple[datetime.datetime | None, dict[str, Any]]],
    window_seconds: int,
    min_count: int,
) -> list[dict[str, Any]] | None:
    """Finds if there is any sliding window of duration <= window_seconds with >= min_count events."""
    if len(events) < min_count:
        return None

    # If any event lacks timestamp, treat all events as co-temporal in the batch
    if any(ts is None for ts, _ in events):
        return [e for _, e in events]

    # Sort events chronologically
    timed_events = [(ts, e) for ts, e in events if ts is not None]
    sorted_timed = sorted(timed_events, key=lambda x: x[0])

    left = 0
    window_delta = datetime.timedelta(seconds=window_seconds)
    max_window_events: list[dict[str, Any]] = []

    for right in range(len(sorted_timed)):
        right_ts = sorted_timed[right][0]
        while right_ts - sorted_timed[left][0] > window_delta:
            left += 1

        current_window = [e for _, e in sorted_timed[left : right + 1]]
        if len(current_window) >= min_count and len(current_window) > len(max_window_events):
            max_window_events = current_window

    return max_window_events if len(max_window_events) >= min_count else None


def _find_windowed_port_scan(
    events: list[tuple[datetime.datetime | None, dict[str, Any]]],
    window_seconds: int,
    min_unique_ports: int,
) -> tuple[set[int], list[dict[str, Any]]] | None:
    """Finds if there is any sliding window with >= min_unique_ports distinct destination ports."""
    if not events:
        return None

    # Check overall unique ports first
    ports_map: list[tuple[datetime.datetime | None, int, dict[str, Any]]] = []
    for ts, e in events:
        p = parse_valid_port(e.get("destination_port"))
        if p is not None:
            ports_map.append((ts, p, e))

    if not ports_map:
        return None

    # If any timestamp is None, evaluate across the whole batch
    if any(ts is None for ts, _, _ in ports_map):
        unique_ports = {p for _, p, _ in ports_map}
        if len(unique_ports) >= min_unique_ports:
            return unique_ports, [e for _, _, e in ports_map]
        return None

    timed_ports = [(ts, p, e) for ts, p, e in ports_map if ts is not None]
    sorted_ports = sorted(timed_ports, key=lambda x: x[0])
    left = 0
    window_delta = datetime.timedelta(seconds=window_seconds)

    max_unique_ports: set[int] = set()
    max_slice_events: list[dict[str, Any]] = []

    for right in range(len(sorted_ports)):
        right_ts = sorted_ports[right][0]
        while right_ts - sorted_ports[left][0] > window_delta:
            left += 1

        window_slice = sorted_ports[left : right + 1]
        unique_in_window = {p for _, p, _ in window_slice}
        if len(unique_in_window) >= min_unique_ports and len(unique_in_window) > len(max_unique_ports):
            max_unique_ports = unique_in_window
            max_slice_events = [e for _, _, e in window_slice]

    if len(max_unique_ports) >= min_unique_ports:
        return max_unique_ports, max_slice_events
    return None


def evaluate_detection_rules(
    events: list[dict[str, Any]],
    window_seconds: int = 300,
    statistical_outliers_count: int = 0,
) -> DetectionResult:
    """Evaluates windowed deterministic SOC rules across normalized event records.

    Rules implemented:
    - RULE_RANSOMWARE_INDICATOR: Mass encryption, ransomware indicators, .locked/.encrypted extensions
    - RULE_BRUTE_FORCE_AUTH: >= 5 failed authentication attempts per (source_ip, user) within sliding window
    - RULE_PORT_SCAN_REJECT: >= 10 distinct destination ports probed per source_ip within sliding window
    """
    if not events:
        return DetectionResult(
            is_attack=False,
            classification="None",
            rule_matches=[],
            statistical_outliers_count=statistical_outliers_count,
            rules_version=RULES_VERSION,
        )

    rule_matches: list[RuleMatch] = []

    # 1. Ransomware Rule
    rw_events: list[dict[str, Any]] = []
    for e in events:
        if not isinstance(e, dict):
            continue
        event_type = str(e.get("event_type", "")).lower()
        details = str(e.get("details", "")).lower()
        if (
            event_type == "ransomware"
            or "ransomware" in details
            or ".locked" in details
            or ".encrypted" in details
        ):
            rw_events.append(e)

    if rw_events:
        matched_ids = [str(e["event_id"]) for e in rw_events if e.get("event_id")]
        rule_matches.append(
            RuleMatch(
                rule_id="RULE_RANSOMWARE_INDICATOR",
                rule_name="Mass File Encryption/Ransomware Indicators",
                confidence=0.95,
                matched_event_ids=matched_ids,
                indicators={"count": len(rw_events)},
            )
        )

    # 2. Brute Force Rule (grouped by (source_ip, user) within sliding window)
    failed_logins: dict[tuple[str, str], list[tuple[datetime.datetime | None, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for e in events:
        if not isinstance(e, dict):
            continue
        status = str(e.get("status", "")).lower()
        event_type = str(e.get("event_type", "")).lower()
        port = parse_valid_port(e.get("destination_port"))

        is_auth = (
            event_type in ("authentication", "login", "ssh_login", "auth")
            or port in (22, 3389)
        )
        is_failure = status in ("failed", "rejected", "failure")

        if is_auth and is_failure:
            src_ip = str(e.get("source_ip") or "unknown").strip()
            user = str(e.get("user") or e.get("username") or "unknown").strip()
            ts = _parse_timestamp(e.get("timestamp"))
            failed_logins[(src_ip, user)].append((ts, e))

    for (ip, user), attempts in failed_logins.items():
        matched_window = _find_windowed_events(attempts, window_seconds=window_seconds, min_count=5)
        if matched_window:
            matched_ids = [str(e["event_id"]) for e in matched_window if e.get("event_id")]
            rule_matches.append(
                RuleMatch(
                    rule_id="RULE_BRUTE_FORCE_AUTH",
                    rule_name="Repeated Failed Authentication Attempts",
                    confidence=0.85,
                    matched_event_ids=matched_ids,
                    indicators={
                        "source_ip": ip,
                        "user": user,
                        "attempt_count": len(matched_window),
                    },
                )
            )

    # 3. Port Scan Rule (grouped by source_ip within sliding window >= 10 distinct ports)
    scans_by_ip: dict[str, list[tuple[datetime.datetime | None, dict[str, Any]]]] = defaultdict(list)
    for e in events:
        if not isinstance(e, dict):
            continue
        src_ip = str(e.get("source_ip") or "").strip()
        port = parse_valid_port(e.get("destination_port"))
        if src_ip and port is not None:
            ts = _parse_timestamp(e.get("timestamp"))
            scans_by_ip[src_ip].append((ts, e))

    for ip, ip_events in scans_by_ip.items():
        scan_match = _find_windowed_port_scan(ip_events, window_seconds=window_seconds, min_unique_ports=10)
        if scan_match:
            unique_ports, matched_slice = scan_match
            matched_ids = [str(e["event_id"]) for e in matched_slice if e.get("event_id")]
            rule_matches.append(
                RuleMatch(
                    rule_id="RULE_PORT_SCAN_REJECT",
                    rule_name="Multi-Port Connection Probing",
                    confidence=0.80,
                    matched_event_ids=matched_ids,
                    indicators={
                        "source_ip": ip,
                        "unique_ports_count": len(unique_ports),
                    },
                )
            )

    # Determine classification precedence hierarchy
    rule_ids = {rm.rule_id for rm in rule_matches}
    if "RULE_RANSOMWARE_INDICATOR" in rule_ids:
        classification = "Ransomware"
    elif "RULE_BRUTE_FORCE_AUTH" in rule_ids:
        classification = "Brute Force"
    elif "RULE_PORT_SCAN_REJECT" in rule_ids:
        classification = "Port Scan"
    elif rule_matches:
        classification = "Suspicious IP Activity"
    else:
        classification = "None"

    return DetectionResult(
        is_attack=len(rule_matches) > 0,
        classification=classification,
        rule_matches=rule_matches,
        statistical_outliers_count=statistical_outliers_count,
        rules_version=RULES_VERSION,
    )
