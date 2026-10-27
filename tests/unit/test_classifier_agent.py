from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from agents.classifier_agent import (
    AttackCategory,
    classify_attack_node,
    deterministic_fallback_classifier,
)


def test_classifier_empty_anomalies_returns_none():
    state = {"anomalies": [], "threat_intel": {}}
    result = classify_attack_node(state)
    assert result == {"attack_classification": "None"}


def test_classifier_with_ollama_success():
    state = {
        "anomalies": [
            {"source_ip": "10.0.0.1", "destination_port": 80, "details": "Suspicious HTTP request"}
        ],
        "threat_intel": {"summary": "Possible web reconnaissance"},
    }

    mock_client = MagicMock()
    mock_client.chat.return_value = {
        "message": {"content": json.dumps({"category": "Port Scan"})}
    }

    with patch("ollama.Client", return_value=mock_client):
        result = classify_attack_node(state)

    assert result["attack_classification"] == "Port Scan"


def test_classifier_fallback_on_ollama_offline_brute_force():
    state = {
        "anomalies": [
            {
                "source_ip": "198.51.100.22",
                "destination_port": 22,
                "event_type": "authentication",
                "status": "failed",
                "details": "Failed SSH password attempt",
            }
            for _ in range(10)
        ],
        "threat_intel": {"summary": "Offline fallback scenario"},
    }

    mock_client = MagicMock()
    mock_client.chat.side_effect = ConnectionRefusedError("Ollama offline")

    with patch("ollama.Client", return_value=mock_client):
        result = classify_attack_node(state)

    assert result["attack_classification"] == "Brute Force"


def test_classifier_fallback_on_malformed_llm_response():
    state = {
        "anomalies": [
            {
                "source_ip": "203.0.113.45",
                "destination_port": 22,
                "event_type": "network",
                "status": "rejected",
                "details": "Closed port 22",
            },
            {
                "source_ip": "203.0.113.45",
                "destination_port": 80,
                "event_type": "network",
                "status": "rejected",
                "details": "Closed port 80",
            },
            {
                "source_ip": "203.0.113.45",
                "destination_port": 443,
                "event_type": "network",
                "status": "rejected",
                "details": "Closed port 443",
            },
        ],
        "threat_intel": {},
    }

    mock_client = MagicMock()
    mock_client.chat.return_value = {"message": {"content": "This looks like a cyber attack."}}

    with patch("ollama.Client", return_value=mock_client):
        result = classify_attack_node(state)

    assert result["attack_classification"] in {cat.value for cat in AttackCategory}
    assert result["attack_classification"] == "Port Scan"


def test_deterministic_fallback_ransomware():
    anomalies = [
        {
            "event_type": "file_access",
            "details": "File modified: /shared/docs/finance.xlsx.encrypted",
            "destination_port": 445,
        }
    ]
    category = deterministic_fallback_classifier(anomalies)
    assert category == AttackCategory.RANSOMWARE
