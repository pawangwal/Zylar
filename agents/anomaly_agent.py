from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest

from agents.state import AgentState
from zylar.analysis.detection_rules import evaluate_detection_rules


def detect_anomalies_node(state: AgentState) -> dict[str, Any]:
    """Uses scikit-learn Isolation Forest to detect statistical anomalies in log frequency and IP behavior,
    correlated with deterministic windowed detection rules.
    """
    events = state.get("parsed_events", [])
    if not events:
        return {
            "anomalies": [],
            "statistical_anomalies": [],
            "rule_matches": [],
            "detection_result": {
                "is_attack": False,
                "classification": "None",
                "rule_matches": [],
                "statistical_outliers_count": 0,
            },
        }

    # 1. Evaluate deterministic detection rules
    detection = evaluate_detection_rules(events)

    # 2. Extract rule-matched event IDs
    rule_matched_ids: set[str] = set()
    for rm in detection.rule_matches:
        rule_matched_ids.update(rm.matched_event_ids)

    rule_matched_events = [
        e for e in events if isinstance(e, dict) and str(e.get("event_id")) in rule_matched_ids
    ]

    # 3. Statistical Anomaly Detection (Isolation Forest)
    df = pd.DataFrame(events)

    statistical_anomalies: list[dict[str, Any]] = []
    if len(df) < 5:
        # Not enough data for meaningful ML anomaly detection, fallback to simple heuristic
        statistical_anomalies = [
            e
            for e in events
            if isinstance(e, dict)
            and (e.get("status") in ["failed", "rejected"] or e.get("event_type") == "ransomware")
        ]
    else:
        # Feature engineering
        ip_counts = df["source_ip"].value_counts().to_dict()
        df["ip_frequency"] = df["source_ip"].map(ip_counts)

        status_map = {"failed": 1, "rejected": 1, "success": 0}
        df["status_num"] = df["status"].map(status_map).fillna(0)

        features = df[["ip_frequency", "status_num"]].fillna(0)

        clf = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        df["anomaly"] = clf.fit_predict(features)
        df["anomaly_score"] = clf.decision_function(features)

        # Filter anomalies (where anomaly == -1)
        anomalies_df = df[df["anomaly"] == -1]

        # Convert to clean records, ensuring NaN is converted to None and integer ports preserved
        records = anomalies_df.drop(columns=["anomaly", "anomaly_score"]).to_dict(orient="records")
        for rec in records:
            clean_rec: dict[str, Any] = {}
            for k, v in rec.items():
                if pd.isna(v):
                    clean_rec[k] = None
                elif k == "destination_port" and v is not None:
                    clean_rec[k] = int(v)
                else:
                    clean_rec[k] = v
            statistical_anomalies.append(clean_rec)

    # 4. Combine rule-matched events and statistical outliers, preserving uniqueness
    seen_identities: set[str] = set()
    combined_anomalies: list[dict[str, Any]] = []

    def _event_key(e: dict[str, Any]) -> str:
        eid = e.get("event_id") or e.get("_id") or e.get("doc_id")
        if eid:
            return f"id:{eid}"
        return f"repr:{sorted((k, str(v)) for k, v in e.items())}"

    # Rule-matched events have priority as confirmed deterministic evidence
    for e in rule_matched_events:
        k = _event_key(e)
        if k not in seen_identities:
            seen_identities.add(k)
            combined_anomalies.append(e)

    # Followed by statistical outliers as candidate leads
    for e in statistical_anomalies:
        k = _event_key(e)
        if k not in seen_identities:
            seen_identities.add(k)
            combined_anomalies.append(e)

    return {
        "anomalies": combined_anomalies,
        "statistical_anomalies": statistical_anomalies,
        "rule_matches": [rm.model_dump() for rm in detection.rule_matches],
        "detection_result": detection.model_dump(),
    }
