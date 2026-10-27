from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_HEX_64_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def compute_raw_event_hash(data: Any) -> str:
    """Computes a deterministic SHA-256 hash from raw event data."""
    if isinstance(data, (dict, list)):
        payload = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
    elif isinstance(data, bytes):
        payload = data.decode("utf-8", errors="replace")
    else:
        payload = str(data)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class NormalizedEvent(BaseModel):
    """Canonical event model for Zylar security events.

    Enforces strict field boundaries, timezone-aware UTC timestamps,
    validated IP addresses, port boundaries, and canonical user identity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(..., min_length=1, max_length=128, description="Stable, non-empty event identifier")
    timestamp: datetime = Field(..., description="Timezone-aware UTC timestamp")
    event_type: str = Field(..., min_length=1, max_length=64, description="Categorical event type")
    source_ip: str | None = Field(default=None, max_length=45, description="Validated IPv4 or IPv6 address")
    user: str | None = Field(default=None, max_length=128, description="Canonical user identity")
    status: str | None = Field(default=None, max_length=64, description="Action outcome or status")
    destination_port: int | None = Field(default=None, description="TCP/UDP port between 1 and 65535")
    details: str | None = Field(default=None, max_length=2048, description="Untrusted event context/payload")
    source: str = Field(default="unknown", min_length=1, max_length=128, description="Event producer identity")
    raw_event_hash: str = Field(..., description="Deterministic SHA-256 hash of raw event payload")

    @model_validator(mode="before")
    @classmethod
    def preprocess_legacy_and_defaults(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        processed = dict(data)

        # Legacy compatibility: map username -> user if user is missing
        if "user" not in processed and "username" in processed:
            processed["user"] = processed.pop("username")

        # Strip whitespace for string keys
        for key in ("event_id", "event_type", "user", "status", "source"):
            val = processed.get(key)
            if isinstance(val, str):
                processed[key] = val.strip()

        # Compute raw_event_hash if omitted
        if not processed.get("raw_event_hash"):
            hash_source = {k: v for k, v in processed.items() if k != "raw_event_hash"}
            processed["raw_event_hash"] = compute_raw_event_hash(hash_source)

        return processed

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("event_id must not be empty or whitespace only")
        return s

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_and_normalize_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str:
                raise ValueError("timestamp must not be empty")
            # Handle trailing 'Z' for ISO 8601
            if v_str.endswith("Z"):
                v_str = v_str[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(v_str)
            except Exception as e:
                raise ValueError(f"Malformed ISO timestamp: '{v}'") from e
        elif isinstance(v, datetime):
            dt = v
        else:
            raise ValueError(f"Unsupported timestamp type: {type(v).__name__}")

        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            raise ValueError("timestamp must be timezone-aware")

        return dt.astimezone(UTC)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        try:
            ip_obj = ipaddress.ip_address(s)
            return str(ip_obj)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: '{v}'") from e

    @field_validator("destination_port", mode="before")
    @classmethod
    def validate_destination_port(cls, v: Any) -> int | None:
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"destination_port must be an integer, got {type(v).__name__}")
        if not (1 <= v <= 65535):
            raise ValueError(f"destination_port must be between 1 and 65535, got {v}")
        return v

    @field_validator("raw_event_hash")
    @classmethod
    def validate_raw_event_hash(cls, v: str) -> str:
        s = v.strip().lower()
        if not _HEX_64_PATTERN.match(s):
            raise ValueError(f"raw_event_hash must be a 64-character hex SHA-256 string, got '{v}'")
        return s


class NormalizationResult(BaseModel):
    """Result container for batch event normalization."""

    events: list[NormalizedEvent] = Field(default_factory=list)
    quarantined: list[dict[str, Any]] = Field(default_factory=list)
    total_processed: int = 0


class EventNormalizer:
    """Normalizes heterogeneous raw log records into canonical NormalizedEvent instances."""

    @classmethod
    def normalize_single(
        cls,
        raw_log: Any,
        default_source: str = "elasticsearch",
    ) -> NormalizedEvent:
        """Normalizes a single log record.

        Extracts Elasticsearch `_source` documents if present, falls back to `_id`
        for event_id if not present in `_source`, and applies canonical field mapping.
        """
        if isinstance(raw_log, NormalizedEvent):
            return raw_log

        if not isinstance(raw_log, dict):
            raise ValueError(f"Expected dict or NormalizedEvent, got {type(raw_log).__name__}")

        # If this is an Elasticsearch hit containing _source
        source_candidate = raw_log.get("_source")
        if isinstance(source_candidate, dict):
            normalized_dict = dict(source_candidate)
        else:
            normalized_dict = dict(raw_log)

        # Preserve / resolve event_id from Elasticsearch document _id fallback
        if not normalized_dict.get("event_id"):
            if raw_log.get("_id"):
                normalized_dict["event_id"] = str(raw_log["_id"])
            else:
                # Documented fallback for raw sources that lack an event_id
                normalized_dict["event_id"] = f"synth-{compute_raw_event_hash(raw_log)[:16]}"

        # Preserve / resolve source metadata from Elasticsearch index or default
        if not normalized_dict.get("source"):
            normalized_dict["source"] = raw_log.get("_index", default_source)

        # Retain raw event hash computed from the outer payload if absent
        if not normalized_dict.get("raw_event_hash"):
            normalized_dict["raw_event_hash"] = compute_raw_event_hash(raw_log)

        return NormalizedEvent.model_validate(normalized_dict)

    @classmethod
    def normalize_batch(
        cls,
        raw_logs: Sequence[Any],
        default_source: str = "elasticsearch",
    ) -> NormalizationResult:
        """Normalizes a batch of log records, segregating valid events from quarantined failures."""
        events: list[NormalizedEvent] = []
        quarantined: list[dict[str, Any]] = []

        for index, item in enumerate(raw_logs):
            try:
                event = cls.normalize_single(item, default_source=default_source)
                events.append(event)
            except Exception as exc:
                quarantined.append({
                    "batch_index": index,
                    "raw_record": item,
                    "error_reason": str(exc),
                })

        return NormalizationResult(
            events=events,
            quarantined=quarantined,
            total_processed=len(raw_logs),
        )
