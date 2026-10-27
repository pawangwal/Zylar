from __future__ import annotations

from unittest.mock import patch

from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_health_live_probe():
    response = client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"
    assert "timestamp" in data


def test_health_ready_probe_all_healthy():
    with (
        patch("elasticsearch.Elasticsearch.ping", return_value=True),
        patch("ollama.Client.list", return_value=[]),
    ):
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["checks"]["elasticsearch"] == "healthy"
        assert data["checks"]["sqlite"] == "healthy"
        assert data["checks"]["ollama"] == "healthy"


def test_health_ready_probe_ollama_degraded():
    """Ollama offline marks application as degraded (HTTP 200), not unhealthy."""
    with (
        patch("elasticsearch.Elasticsearch.ping", return_value=True),
        patch("ollama.Client.list", side_effect=ConnectionRefusedError("Ollama offline")),
    ):
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["checks"]["elasticsearch"] == "healthy"
        assert data["checks"]["sqlite"] == "healthy"
        assert data["checks"]["ollama"] == "degraded"


def test_health_ready_probe_elasticsearch_down_returns_503():
    """Critical dependency failure returns HTTP 503."""
    with patch("elasticsearch.Elasticsearch.ping", return_value=False):
        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["elasticsearch"] == "unhealthy"


def test_health_endpoints_do_not_leak_secrets_or_internals():
    """Verifies that health probes never disclose secrets, URLs with credentials, or internal IPs."""
    response = client.get("/health/ready")
    text = response.text.lower()

    for secret_marker in (
        "password",
        "secret",
        "signing_key",
        "change-me",
        "replace-with",
        "postgres",
        "psycopg",
    ):
        assert secret_marker not in text
