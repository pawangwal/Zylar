from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IncidentResponse(BaseModel):
    """Canonical response envelope for workflow incident execution."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str | None = Field(default=None, description="Unique incident identifier")
    attack_classification: str = Field(..., description="Classified attack category or 'None'")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic or model risk score between 0 and 100")
    risk_category: str = Field(..., description="Categorical risk band (Low, Medium, High, Critical)")
    mitigation_plan: list[str] = Field(default_factory=list, description="Advisory remediation recommendations")


class ComponentHealth(BaseModel):
    """Health status and diagnostic details of an individual dependency."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Component state: healthy, degraded, or unhealthy")
    details: dict[str, Any] | None = Field(default=None, description="Optional diagnostic metrics or latency")


class HealthResponse(BaseModel):
    """Structured health check response for liveness and readiness probes."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Aggregated service health: healthy, degraded, or unhealthy")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timezone-aware UTC timestamp of the health evaluation",
    )
    components: dict[str, ComponentHealth] = Field(
        default_factory=dict,
        description="Health states of external dependencies",
    )


class ErrorResponse(BaseModel):
    """Generic error envelope avoiding internal traceback leaks."""

    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., description="High-level error classification or safe message")
    correlation_id: str = Field(..., description="Request or execution tracking ID for server-side log correlation")
    details: str | None = Field(default=None, description="Safe client-facing explanatory context")
