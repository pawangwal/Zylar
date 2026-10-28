from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from api.main import app
from fastapi.testclient import TestClient

from zylar.persistence.database import DatabaseManager

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_lifespan_db_manager():
    """Simulates the lifespan-managed DatabaseManager on app.state."""
    mock_mgr = MagicMock(spec=DatabaseManager)
    mock_mgr.check_connection.return_value = True
    app.state.db_manager = mock_mgr
    yield mock_mgr
    if hasattr(app.state, "db_manager"):
        delattr(app.state, "db_manager")


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
        assert data["checks"]["database"] == "healthy"
        assert "sqlite" not in data["checks"]
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
        assert data["checks"]["database"] == "healthy"
        assert "sqlite" not in data["checks"]
        assert data["checks"]["ollama"] == "degraded"


def test_health_ready_probe_elasticsearch_down_returns_503():
    """Critical dependency failure returns HTTP 503."""
    with patch("elasticsearch.Elasticsearch.ping", return_value=False):
        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["elasticsearch"] == "unhealthy"


def test_health_ready_probe_database_down_returns_503(setup_lifespan_db_manager):
    """Database critical dependency failure returns HTTP 503."""
    setup_lifespan_db_manager.check_connection.return_value = False
    with patch("elasticsearch.Elasticsearch.ping", return_value=True):
        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["database"] == "unhealthy"
        assert "sqlite" not in data["checks"]


def test_health_ready_probe_database_exception_returns_503(setup_lifespan_db_manager):
    """Database connection exception is handled gracefully and returns HTTP 503."""
    from zylar.persistence.exceptions import DatabaseConnectionError

    setup_lifespan_db_manager.check_connection.side_effect = DatabaseConnectionError(
        "Connection refused to PostgreSQL host"
    )
    with patch("elasticsearch.Elasticsearch.ping", return_value=True):
        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["database"] == "unhealthy"
        assert "sqlite" not in data["checks"]


def test_health_ready_probe_fails_without_lifespan_db_manager():
    """Readiness probe strictly requires lifespan-managed app.state.db_manager and returns 503 if missing."""
    if hasattr(app.state, "db_manager"):
        delattr(app.state, "db_manager")
    with patch("elasticsearch.Elasticsearch.ping", return_value=True):
        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["database"] == "unhealthy"
        assert "sqlite" not in data["checks"]


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
