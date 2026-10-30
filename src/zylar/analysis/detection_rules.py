from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from zylar.analysis.risk_scoring import parse_valid_port

RULES_VERSION: str = "2026.10.1"


class RuleMatch(BaseModel):
    """Immutable representation of a deterministic detection rule match."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    confidence: float
    matched_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    indicators: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """Immutable outcome of deterministic rule evaluation."""

    model_config = ConfigDict(frozen=True)

    is_attack: bool
    classification: str
    rule_matches: tuple[RuleMatch, ...] = Field(default_factory=tuple)
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
    """Finds if there is any sliding window of duration <= window_seconds with >= min_count events.

    Events lacking a valid timestamp are excluded from sliding-window calculation because
    unverifiable time placement cannot satisfy temporal threshold constraints.
    """
    # Exclude events without verified timestamps
    timed_events = [(ts, e) for ts, e in events if ts is not None]
    if len(timed_events) < min_count:
        return None

    # Sort events chronologically
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
    """Finds if there is any sliding window with >= min_unique_ports distinct destination ports.

    Events lacking a valid timestamp are excluded from sliding-window calculation.
    """
    if not events:
        return None

    # Map only valid destination ports with valid timestamps
    ports_map: list[tuple[datetime.datetime, int, dict[str, Any]]] = []
    for ts, e in events:
        if ts is not None:
            p = parse_valid_port(e.get("destination_port"))
            if p is not None:
                ports_map.append((ts, p, e))

    if len(ports_map) < min_unique_ports:
        return None

    sorted_ports = sorted(ports_map, key=lambda x: x[0])
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
            rule_matches=(),
            statistical_outliers_count=statistical_outliers_count,
            rules_version=RULES_VERSION,
        )

    rule_matches: list[RuleMatch] = []

    # 1. Ransomware Detection:
    # 1a. RULE_RANSOMWARE_INDICATOR: File extension / keyword indicators on individual events
    rw_indicator_events: list[dict[str, Any]] = []
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
            rw_indicator_events.append(e)

    if rw_indicator_events:
        matched_ids = [str(e["event_id"]) for e in rw_indicator_events if e.get("event_id")]
        rule_matches.append(
            RuleMatch(
                rule_id="RULE_RANSOMWARE_INDICATOR",
                rule_name="Ransomware File Extension/Keyword Indicator",
                confidence=0.90,
                matched_event_ids=tuple(matched_ids),
                indicators={"count": len(rw_indicator_events)},
            )
        )

    # 1b. RULE_RANSOMWARE_MASS_ENCRYPTION: >= 20 file encryption events for same entity within sliding window
    mass_encryptions: dict[tuple[str, str], list[tuple[datetime.datetime | None, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for e in events:
        if not isinstance(e, dict):
            continue
        event_type = str(e.get("event_type", "")).lower()
        details = str(e.get("details", "")).lower()
        is_encryption = (
            event_type in ("file_encryption", "file_modification", "file_encrypt", "ransomware")
            or "encrypt" in event_type
            or "encrypt" in details
            or ".locked" in details
            or ".encrypted" in details
        )
        if is_encryption:
            src_ip = str(e.get("source_ip") or e.get("host") or "unknown").strip()
            user = str(e.get("user") or e.get("username") or "unknown").strip()
            ts = _parse_timestamp(e.get("timestamp"))
            mass_encryptions[(src_ip, user)].append((ts, e))

    for (ip, user), attempts in mass_encryptions.items():
        matched_window = _find_windowed_events(attempts, window_seconds=window_seconds, min_count=20)
        if matched_window:
            matched_ids = [str(e["event_id"]) for e in matched_window if e.get("event_id")]
            rule_matches.append(
                RuleMatch(
                    rule_id="RULE_RANSOMWARE_MASS_ENCRYPTION",
                    rule_name="Mass File Encryption Attack",
                    confidence=0.98,
                    matched_event_ids=tuple(matched_ids),
                    indicators={
                        "source_ip": ip,
                        "user": user,
                        "encryption_count": len(matched_window),
                    },
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
            event_type in ("authentication", "login", "ssh_login", "auth", "auth_failure")
            or "auth" in event_type
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
                    matched_event_ids=tuple(matched_ids),
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
                    matched_event_ids=tuple(matched_ids),
                    indicators={
                        "source_ip": ip,
                        "unique_ports_count": len(unique_ports),
                    },
                )
            )

    # Determine classification precedence hierarchy
    rule_ids = {rm.rule_id for rm in rule_matches}
    if "RULE_RANSOMWARE_MASS_ENCRYPTION" in rule_ids or "RULE_RANSOMWARE_INDICATOR" in rule_ids:
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
        rule_matches=tuple(rule_matches),
        statistical_outliers_count=statistical_outliers_count,
        rules_version=RULES_VERSION,
    )
