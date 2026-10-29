from __future__ import annotations

from unittest.mock import patch

import pytest
from api.main import app
from fastapi.testclient import TestClient

from zylar.core.security import Role, create_access_token, get_user_store

client = TestClient(app)


@pytest.fixture(autouse=True)
def ensure_test_users():
    """Ensures analyst and viewer users exist in user store for RBAC tests."""
    store = get_user_store()
    if not store.get_user("analyst_test"):
        store.create_user("analyst_test", "AnalystPass123!", Role.ANALYST)
    if not store.get_user("viewer_test"):
        store.create_user("viewer_test", "ViewerPass123!", Role.VIEWER)


def test_token_endpoint_authenticates_bootstrap_admin():
    from zylar.core.settings import get_settings

    settings = get_settings()
    response = client.post(
        "/api/auth/token",
        json={
            "username": settings.bootstrap_admin_username,
            "password": settings.bootstrap_admin_password.get_secret_value(),
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"].lower() == "bearer"
    assert data["role"] == "admin"


def test_token_endpoint_rejects_invalid_password():
    from zylar.core.settings import get_settings

    settings = get_settings()
    response = client.post(
        "/api/auth/token",
        json={"username": settings.bootstrap_admin_username, "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.text


def test_token_endpoint_rejects_unknown_user():
    response = client.post(
        "/api/auth/token",
        json={"username": "non_existent_user", "password": "any-password"},
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "route", "body"),
    [
        ("post", "/api/workflow/run", {"events": []}),
        ("get", "/api/logs/recent", None),
        ("get", "/api/reports", None),
        ("get", "/api/offenders", None),
    ],
)
def test_unauthenticated_requests_return_401(method: str, route: str, body: dict | None):
    if method == "post":
        response = client.post(route, json=body)
    else:
        response = client.get(route)
    assert response.status_code == 401
    assert (
        "Authorization" in response.text
        or "credentials" in response.text
        or "token" in response.text.lower()
    )


def test_workflow_run_rbac_viewer_forbidden():
    viewer_token = create_access_token("viewer_test", Role.VIEWER)
    headers = {"Authorization": f"Bearer {viewer_token}"}
    payload = {
        "events": [
            {
                "event_id": "test-1",
                "timestamp": "2026-10-25T14:00:00Z",
                "event_type": "network",
            }
        ]
    }
    response = client.post("/api/workflow/run", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Forbidden" in response.text


def test_workflow_run_rbac_analyst_and_admin_allowed():
    payload = {
        "events": [
            {
                "event_id": "test-1",
                "timestamp": "2026-10-25T14:00:00Z",
                "event_type": "network",
                "source_ip": "10.0.0.1",
            }
        ]
    }

    with patch("ollama.Client"):
        # Analyst allowed
        analyst_token = create_access_token("analyst_test", Role.ANALYST)
        res_analyst = client.post(
            "/api/workflow/run",
            json=payload,
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_analyst.status_code == 200

        # Admin allowed
        admin_token = create_access_token("admin", Role.ADMIN)
        res_admin = client.post(
            "/api/workflow/run",
            json=payload,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res_admin.status_code == 200


def test_read_routes_accessible_by_authenticated_viewer():
    viewer_token = create_access_token("viewer_test", Role.VIEWER)
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # /api/reports
    res_reports = client.get("/api/reports", headers=headers)
    assert res_reports.status_code == 200

    # /api/offenders
    res_offenders = client.get("/api/offenders", headers=headers)
    assert res_offenders.status_code == 200


def test_request_correlation_id_propagated():
    # When client sends X-Correlation-ID
    client_corr_id = "test-corr-id-12345"
    response = client.post(
        "/api/auth/token",
        json={"username": "admin", "password": "change-admin-password-in-production"},
        headers={"X-Correlation-ID": client_corr_id},
    )
    assert response.headers.get("X-Correlation-ID") == client_corr_id

    # When client does not send X-Correlation-ID, server generates one
    res_auto = client.post(
        "/api/auth/token",
        json={"username": "admin", "password": "change-admin-password-in-production"},
    )
    generated_id = res_auto.headers.get("X-Correlation-ID")
    assert generated_id is not None
    assert generated_id.startswith("req-")


def test_exception_redaction_on_workflow_failure():
    analyst_token = create_access_token("analyst_test", Role.ANALYST)
    payload = {
        "events": [
            {
                "event_id": "test-1",
                "timestamp": "2026-10-25T14:00:00Z",
                "event_type": "network",
                "source_ip": "10.0.0.1",
            }
        ]
    }
    with patch("api.main.build_workflow") as mock_wf:
        mock_wf.side_effect = RuntimeError("sensitive_internal_connection_failure_host_secret_db")
        res = client.post(
            "/api/workflow/run",
            json=payload,
            headers={
                "Authorization": f"Bearer {analyst_token}",
                "X-Correlation-ID": "test-redact-corr",
            },
        )
    assert res.status_code == 500
    data = res.json()
    assert "error" in data
    # Sensitive internal error must be completely redacted from the client response
    assert "sensitive_internal_connection_failure_host_secret_db" not in data["error"]
    assert data["error"] == "Workflow execution failed due to an internal processing error."
    assert data["correlation_id"] == "test-redact-corr"


def test_exception_redaction_on_logs_failure():
    viewer_token = create_access_token("viewer_test", Role.VIEWER)
    with patch("api.main.Elasticsearch") as mock_es:
        mock_es.return_value.search.side_effect = ConnectionError(
            "internal_es_failed_on_private_port_9200"
        )
        res = client.get(
            "/api/logs/recent",
            headers={"Authorization": f"Bearer {viewer_token}", "X-Correlation-ID": "test-es-fail"},
        )
    assert res.status_code == 502
    data = res.json()
    assert "internal_es_failed_on_private_port_9200" not in data["error"]
    assert data["error"] == "Failed to retrieve recent logs from search backend."
    assert data["correlation_id"] == "test-es-fail"


def test_exception_redaction_on_offenders_failure():
    viewer_token = create_access_token("viewer_test", Role.VIEWER)
    with patch("api.main.get_top_offenders", side_effect=Exception("sqlite_table_locked_on_disk")):
        res = client.get(
            "/api/offenders",
            headers={
                "Authorization": f"Bearer {viewer_token}",
                "X-Correlation-ID": "test-sqlite-fail",
            },
        )
    assert res.status_code == 502
    data = res.json()
    assert "sqlite_table_locked_on_disk" not in data["error"]
    assert data["error"] == "Failed to retrieve offender statistics from storage backend."
    assert data["correlation_id"] == "test-sqlite-fail"
