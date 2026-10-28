from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest

from agents.state import AgentState


def detect_anomalies_node(state: AgentState) -> dict[str, Any]:
    """Uses scikit-learn Isolation Forest to detect statistical anomalies in log frequency and IP behavior."""
    events = state.get("parsed_events", [])
    if not events:
        return {"anomalies": []}

    df = pd.DataFrame(events)

    if len(df) < 5:
        # Not enough data for meaningful ML anomaly detection, fallback to simple heuristic
        anomalies = [
            e
            for e in events
            if e.get("status") in ["failed", "rejected"] or e.get("event_type") == "ransomware"
        ]
        return {"anomalies": anomalies}

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
    clean_anomalies: list[dict[str, Any]] = []
    for rec in records:
        clean_rec: dict[str, Any] = {}
        for k, v in rec.items():
            if pd.isna(v):
                clean_rec[k] = None
            elif k == "destination_port" and v is not None:
                clean_rec[k] = int(v)
            else:
                clean_rec[k] = v
        clean_anomalies.append(clean_rec)

    return {"anomalies": clean_anomalies}
