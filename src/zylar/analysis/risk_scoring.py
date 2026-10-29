from __future__ import annotations

import math
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_CLASSIFICATION_SEVERITIES: dict[str, int] = {
    "Ransomware": 100,
    "DDoS": 90,
    "Brute Force": 60,
    "Suspicious IP Activity": 50,
    "Port Scan": 30,
    "None": 0,
}

DEFAULT_PORT_CRITICALITIES: dict[int, int] = {
    22: 90,  # SSH
    3389: 90,  # RDP
    445: 95,  # SMB
    443: 70,  # HTTPS
    80: 60,  # HTTP
}


def parse_valid_port(port_val: Any) -> int | None:
    """Parses destination port strictly: accepts only non-boolean ints and integer-formatted strings in range 1-65535.

    Rejects booleans, fractional floats (e.g. 22.5), float strings (e.g. '22.5'), and out-of-range ports.
    """
    if isinstance(port_val, bool) or port_val is None:
        return None
    if isinstance(port_val, int):
        return port_val if 1 <= port_val <= 65535 else None
    if isinstance(port_val, str):
        s = port_val.strip()
        if s.isdigit():
            val = int(s)
            return val if 1 <= val <= 65535 else None
        return None
    return None


_parse_valid_port = parse_valid_port


def _validate_numeric_factor(val: Any, field_name: str) -> float:
    """Validates and extracts float value; rejects booleans, non-numbers, NaN, and Infinity."""
    if isinstance(val, bool):
        raise ValueError(f"Boolean values are not valid numeric inputs for '{field_name}'")
    if val is None:
        return 0.0
    try:
        fval = float(val)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid non-numeric input for '{field_name}': {val!r}") from exc
    if math.isnan(fval) or math.isinf(fval):
        raise ValueError(f"Numeric input for '{field_name}' must be a finite number, got {val}")
    return fval


class RiskPolicy(BaseModel):
    """Immutable, versioned policy defining risk weights, severities, criticality, and thresholds."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    policy_version: str = "risk-policy-v1"
    weight_volume: float = 0.25
    weight_severity: float = 0.25
    weight_recurrence: float = 0.20
    weight_centrality: float = 0.15
    weight_criticality: float = 0.15

    classification_severities: Mapping[str, int] = Field(
        default_factory=lambda: MappingProxyType(dict(DEFAULT_CLASSIFICATION_SEVERITIES))
    )
    port_criticalities: Mapping[int, int] = Field(
        default_factory=lambda: MappingProxyType(dict(DEFAULT_PORT_CRITICALITIES))
    )
    default_port_criticality: int = 50

    # Configurable, ordered category thresholds
    threshold_critical: int = 80
    threshold_high: int = 60
    threshold_medium: int = 40

    # Centrality scale contract: "0-100" (percentage scale, default) or "0-1" (unit scale)
    centrality_scale: str = "0-100"

    @model_validator(mode="before")
    @classmethod
    def _prepare_mappings(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # Wrap dictionaries into MappingProxyType for deep immutability
            if "classification_severities" in values and isinstance(
                values["classification_severities"], dict
            ):
                merged_sev = dict(DEFAULT_CLASSIFICATION_SEVERITIES)
                merged_sev.update(values["classification_severities"])
                values["classification_severities"] = MappingProxyType(merged_sev)
            if "port_criticalities" in values and isinstance(values["port_criticalities"], dict):
                merged_ports = dict(DEFAULT_PORT_CRITICALITIES)
                merged_ports.update(values["port_criticalities"])
                values["port_criticalities"] = MappingProxyType(merged_ports)
        return values

    @model_validator(mode="after")
    def _validate_policy(self) -> RiskPolicy:
        weights = [
            self.weight_volume,
            self.weight_severity,
            self.weight_recurrence,
            self.weight_centrality,
            self.weight_criticality,
        ]
        for w in weights:
            if w < 0.0 or w > 1.0:
                raise ValueError(f"Each policy weight must be between 0.0 and 1.0, got {w}")

        weight_sum = sum(weights)
        if not math.isclose(weight_sum, 1.0, abs_tol=1e-4):
            raise ValueError(
                f"Weights must sum to 1.0, but sum was {weight_sum:.4f} "
                f"(volume={self.weight_volume}, severity={self.weight_severity}, "
                f"recurrence={self.weight_recurrence}, centrality={self.weight_centrality}, "
                f"criticality={self.weight_criticality})"
            )

        for name, sev in self.classification_severities.items():
            if not (0 <= sev <= 100):
                raise ValueError(
                    f"Severity scores must be between 0 and 100, got {sev} for '{name}'"
                )

        for port, crit in self.port_criticalities.items():
            if not (1 <= port <= 65535):
                raise ValueError(f"Port number must be between 1 and 65535, got {port}")
            if not (0 <= crit <= 100):
                raise ValueError(
                    f"Criticality scores must be between 0 and 100, got {crit} for port {port}"
                )

        if not (0 <= self.default_port_criticality <= 100):
            raise ValueError(
                f"default_port_criticality must be between 0 and 100, got {self.default_port_criticality}"
            )

        if not (0 < self.threshold_medium < self.threshold_high < self.threshold_critical <= 100):
            raise ValueError(
                f"Thresholds must be strictly ordered (0 < medium < high < critical <= 100), "
                f"got medium={self.threshold_medium}, high={self.threshold_high}, critical={self.threshold_critical}"
            )

        if self.centrality_scale not in ("0-100", "0-1"):
            raise ValueError(
                f"centrality_scale must be '0-100' or '0-1', got {self.centrality_scale!r}"
            )

        if not isinstance(self.classification_severities, MappingProxyType):
            object.__setattr__(
                self,
                "classification_severities",
                MappingProxyType(dict(self.classification_severities)),
            )
        if not isinstance(self.port_criticalities, MappingProxyType):
            object.__setattr__(
                self, "port_criticalities", MappingProxyType(dict(self.port_criticalities))
            )

        return self

    def get_classification_severity(self, classification: str) -> int:
        """Looks up classification severity case-insensitively with default fallback."""
        cleaned = classification.strip().lower()
        for k, v in self.classification_severities.items():
            if k.strip().lower() == cleaned:
                return v
        return 40  # Default severity for unknown classifications


class RiskScoreResult(BaseModel):
    """Immutable outcome of deterministic risk evaluation."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    risk_score: int
    risk_category: str
    policy_version: str
    raw_factors: Mapping[str, float]
    weighted_contributions: Mapping[str, float]

    @model_validator(mode="after")
    def _freeze_mappings(self) -> RiskScoreResult:
        if not isinstance(self.raw_factors, MappingProxyType):
            object.__setattr__(self, "raw_factors", MappingProxyType(dict(self.raw_factors)))
        if not isinstance(self.weighted_contributions, MappingProxyType):
            object.__setattr__(
                self, "weighted_contributions", MappingProxyType(dict(self.weighted_contributions))
            )
        return self

    @property
    def breakdown(self) -> Mapping[str, float]:
        """Backward-compatible factor breakdown returning raw factor values."""
        return self.raw_factors


DEFAULT_RISK_POLICY = RiskPolicy()


def evaluate_risk(
    state: dict[str, Any],
    policy: RiskPolicy | None = None,
) -> RiskScoreResult:
    """Pure, deterministic risk scoring function."""
    active_policy = policy or DEFAULT_RISK_POLICY
    raw_classification = str(state.get("attack_classification") or "None").strip()
    anomalies = state.get("anomalies") or []

    if not anomalies or raw_classification.lower() == "none" or not raw_classification:
        zero_raw = MappingProxyType(
            {
                "volume": 0.0,
                "severity": 0.0,
                "recurrence": 0.0,
                "centrality": 0.0,
                "criticality": 0.0,
            }
        )
        zero_weighted = MappingProxyType(
            {
                "volume": 0.0,
                "severity": 0.0,
                "recurrence": 0.0,
                "centrality": 0.0,
                "criticality": 0.0,
            }
        )
        return RiskScoreResult(
            risk_score=0,
            risk_category="Low",
            policy_version=active_policy.policy_version,
            raw_factors=zero_raw,
            weighted_contributions=zero_weighted,
        )

    # 1. Severity factor (0 - 100) with case-insensitive matching
    severity = float(active_policy.get_classification_severity(raw_classification))

    # 2. Anomaly Volume factor (0 - 100 proxy using volume)
    valid_anomalies_count = sum(1 for a in anomalies if isinstance(a, dict))
    volume_conf = float(min(100, valid_anomalies_count * 5))

    # 3. Historical Recurrence factor (0 - 100 clamped with strict numeric validation)
    raw_recurrence = _validate_numeric_factor(
        state.get("historical_recurrence", 0), "historical_recurrence"
    )
    recurrence = float(min(100.0, max(0.0, raw_recurrence)))

    # 4. Graph Centrality factor (strictly validated and scale-normalized)
    raw_centrality = _validate_numeric_factor(
        state.get("graph_centrality", 0.0), "graph_centrality"
    )
    if active_policy.centrality_scale == "0-1":
        centrality = float(min(100.0, max(0.0, raw_centrality * 100.0)))
    else:
        centrality = float(min(100.0, max(0.0, raw_centrality)))

    # 5. Asset Criticality factor (0 - 100 based on destination ports 1-65535)
    target_ports: set[int] = set()
    for a in anomalies:
        if isinstance(a, dict) and "destination_port" in a:
            parsed_port = _parse_valid_port(a["destination_port"])
            if parsed_port is not None:
                target_ports.add(parsed_port)

    criticality = float(active_policy.default_port_criticality)
    if target_ports:
        port_scores = [
            active_policy.port_criticalities.get(p, active_policy.default_port_criticality)
            for p in target_ports
        ]
        criticality = float(max(port_scores))

    # Weighted Formula
    weighted_vol = volume_conf * active_policy.weight_volume
    weighted_sev = severity * active_policy.weight_severity
    weighted_rec = recurrence * active_policy.weight_recurrence
    weighted_cen = centrality * active_policy.weight_centrality
    weighted_crit = criticality * active_policy.weight_criticality

    total_weighted = weighted_vol + weighted_sev + weighted_rec + weighted_cen + weighted_crit
    final_score = int(min(100, max(0, round(total_weighted))))

    if final_score >= active_policy.threshold_critical:
        cat = "Critical"
    elif final_score >= active_policy.threshold_high:
        cat = "High"
    elif final_score >= active_policy.threshold_medium:
        cat = "Medium"
    else:
        cat = "Low"

    raw_factors = {
        "volume": volume_conf,
        "severity": severity,
        "recurrence": recurrence,
        "centrality": centrality,
        "criticality": criticality,
    }
    weighted_contributions = {
        "volume": weighted_vol,
        "severity": weighted_sev,
        "recurrence": weighted_rec,
        "centrality": weighted_cen,
        "criticality": weighted_crit,
    }

    return RiskScoreResult(
        risk_score=final_score,
        risk_category=cat,
        policy_version=active_policy.policy_version,
        raw_factors=MappingProxyType(raw_factors),
        weighted_contributions=MappingProxyType(weighted_contributions),
    )
