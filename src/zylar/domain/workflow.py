from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zylar.core.settings import get_settings
from zylar.domain.events import EventNormalizer, NormalizedEvent


class WorkflowRequest(BaseModel):
    """Workflow execution request payload containing a bounded batch of canonical events."""

    model_config = ConfigDict(extra="forbid")

    events: list[NormalizedEvent] = Field(
        ...,
        min_length=1,
        max_length=get_settings().max_batch_size,
        description="Bounded list of normalized security events",
    )
    allow_duplicate_ids: bool = Field(
        default=False,
        description="Policy toggle indicating whether duplicate event IDs are permitted in a single batch",
    )

    @model_validator(mode="before")
    @classmethod
    def preprocess_raw_events(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data = dict(data)
            # If "logs" was sent instead of "events", support for backward compatibility and remove "logs" key
            raw_list = data.get("events")
            if raw_list is None and "logs" in data:
                raw_list = data.pop("logs")

            if isinstance(raw_list, list):
                max_batch = get_settings().max_batch_size
                if len(raw_list) > max_batch:
                    raise ValueError(
                        f"Event batch size exceeds maximum limit of {max_batch} events (got {len(raw_list)})"
                    )

                normalized = []
                for item in raw_list:
                    if isinstance(item, NormalizedEvent):
                        normalized.append(item)
                    else:
                        normalized.append(EventNormalizer.normalize_single(item))
                data["events"] = normalized
        return data

    @model_validator(mode="after")
    def validate_unique_event_ids(self) -> Self:
        if not self.allow_duplicate_ids:
            seen_ids: set[str] = set()
            duplicates: list[str] = []
            for ev in self.events:
                if ev.event_id in seen_ids:
                    duplicates.append(ev.event_id)
                seen_ids.add(ev.event_id)
            if duplicates:
                raise ValueError(f"Duplicate event IDs found in workflow request: {duplicates}")
        return self
