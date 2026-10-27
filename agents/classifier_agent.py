from __future__ import annotations

import json
import logging
from enum import StrEnum
from typing import Any

import ollama
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agents.state import AgentState
from zylar.core.settings import get_settings

logger = logging.getLogger(__name__)


class AttackCategory(StrEnum):
    """Canonical attack classification categories."""

    BRUTE_FORCE = "Brute Force"
    PORT_SCAN = "Port Scan"
    RANSOMWARE = "Ransomware"
    SUSPICIOUS_IP_ACTIVITY = "Suspicious IP Activity"
    DDOS = "DDoS"
    UNKNOWN = "Unknown"
    NONE = "None"


class AttackClassificationResult(BaseModel):
    """Pydantic validation schema for local LLM classification responses."""

    model_config = ConfigDict(extra="ignore")

    category: AttackCategory = Field(default=AttackCategory.UNKNOWN)


def deterministic_fallback_classifier(anomalies: list[dict[str, Any]]) -> AttackCategory:
    """Deterministic heuristic classifier used when local AI is unavailable or produces malformed output.

    Evaluates observable anomaly telemetry: ports, event types, status, and payload details.
    """
    if not anomalies:
        return AttackCategory.NONE

    # Check for Ransomware indicators (encrypted file extensions, SMB port 445)
    for a in anomalies:
        details = str(a.get("details", "")).lower()
        event_type = str(a.get("event_type", "")).lower()
        if ".encrypted" in details or "ransom" in details or event_type == "ransomware":
            return AttackCategory.RANSOMWARE

    # Check for Port Scan indicators (multiple distinct destination ports, network rejections)
    ports = {a.get("destination_port") for a in anomalies if a.get("destination_port") is not None}
    if len(ports) >= 3:
        return AttackCategory.PORT_SCAN

    # Check for Brute Force indicators (failed authentication, SSH port 22, repetitive auth failures)
    failed_auth_count = sum(
        1
        for a in anomalies
        if a.get("status") in ("failed", "rejected")
        or a.get("event_type") == "authentication"
        or a.get("destination_port") == 22
    )
    if failed_auth_count >= 3:
        return AttackCategory.BRUTE_FORCE

    # Check for Suspicious IP Activity (geo-policy violations, strange subnets)
    for a in anomalies:
        details = str(a.get("details", "")).lower()
        if "geo" in details or "policy violation" in details or "suspicious" in details:
            return AttackCategory.SUSPICIOUS_IP_ACTIVITY

    if len(anomalies) >= 50:
        return AttackCategory.DDOS

    return AttackCategory.UNKNOWN


def classify_attack_node(state: AgentState) -> dict[str, Any]:
    """Classifies attack type using local Ollama model with Pydantic validation and deterministic fallbacks.

    Completely offline: never invokes external AI providers or network APIs.
    """
    intel = state.get("threat_intel", {})
    anomalies = state.get("anomalies", [])

    if not anomalies:
        return {"attack_classification": AttackCategory.NONE.value}

    settings = get_settings()

    prompt = f"""You are an Attack Classification Agent.
Based on the following threat intel and anomalous events, classify the attack into ONE of these categories:
- Brute Force
- Port Scan
- Ransomware
- Suspicious IP Activity
- DDoS
- Unknown

Threat Intel: {json.dumps(intel, default=str)}
Number of Anomalous Events: {len(anomalies)}
Sample anomaly details: {[a.get('details') for a in anomalies[:3]]}
Targeted ports: {list({a.get('destination_port') for a in anomalies if a.get('destination_port')})[:10]}

Respond ONLY in valid JSON format with the key "category". Example: {{"category": "Brute Force"}}"""

    try:
        client = ollama.Client(
            host=str(settings.ollama_url),
            timeout=settings.request_timeout_seconds,
        )
        response = client.chat(
            model=settings.ollama_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity attack classification assistant. Always respond in valid JSON with key 'category'.",
                },
                {"role": "user", "content": prompt},
            ],
            options={"temperature": 0.0},
        )
        content = response["message"]["content"].strip()

        # Parse JSON from markdown fences if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].strip()

        parsed_json = json.loads(content)
        validated_result = AttackClassificationResult.model_validate(parsed_json)
        classification = validated_result.category.value

    except (ollama.ResponseError, ConnectionError, OSError, json.JSONDecodeError, ValidationError, Exception) as exc:
        logger.warning(
            "Local Ollama classification failed or malformed (%s), activating deterministic fallback: %s",
            type(exc).__name__,
            exc,
        )
        fallback_cat = deterministic_fallback_classifier(anomalies)
        classification = fallback_cat.value

    return {"attack_classification": classification}
