from __future__ import annotations

import logging
import pkgutil
from datetime import UTC, datetime

from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_correlation_id_valid_header_accepted_and_echoed():
    valid_id = "corr-123_abc.XYZ-456"
    response = client.get("/health/live", headers={"X-Correlation-ID": valid_id})
    assert response.status_code == 200
    assert response.headers.get("X-Correlation-ID") == valid_id


def test_correlation_id_oversized_returns_400_bad_request():
    oversized_id = "a" * 129
    response = client.get("/health/live", headers={"X-Correlation-ID": oversized_id})
    assert response.status_code == 400
    data = response.json()
    assert "Invalid X-Correlation-ID" in data.get("error", "")
    assert "X-Correlation-ID" in response.headers


def test_correlation_id_disallowed_characters_returns_400_bad_request():
    disallowed_ids = [
        "bad id with spaces",
        "<script>alert(1)</script>",
        "corr;drop table incidents;",
        "user@host:5432",
        "corr$variable",
    ]
    for bad_id in disallowed_ids:
        response = client.get("/health/live", headers={"X-Correlation-ID": bad_id})
        assert response.status_code == 400
        data = response.json()
        assert "Invalid X-Correlation-ID" in data.get("error", "")


def test_generic_exception_handler_sanitizes_sentinel_secret(caplog):
    """Verifies that an unhandled exception containing a secret does not leak into logs or API responses."""
    sentinel_secret = "SENTINEL_SECRET_DATABASE_PASSWORD_998877"

    @app.get("/api/test-secret-leakage-path")
    async def route_that_raises():
        raise RuntimeError(f"Database auth failure with secret: {sentinel_secret}")

    error_client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG):
        response = error_client.get("/api/test-secret-leakage-path")

    assert response.status_code == 500
    data = response.json()
    # Response must be generic and correlation-ID-bearing
    assert data["error"] == "Internal server error"
    assert "correlation_id" in data
    assert sentinel_secret not in response.text

    # Captured log records must not contain the secret or full traceback with variable inspection
    assert sentinel_secret not in caplog.text
    # Logged line must state the exception class name cleanly without raw payload
    assert "RuntimeError" in caplog.text


def test_sqlite_retirement_no_active_persistence_call_sites():
    """Verifies that memory.sqlite_manager is deleted and no runtime module references it."""
    import importlib.util

    try:
        spec = importlib.util.find_spec("memory.sqlite_manager")
        assert spec is None
    except ModuleNotFoundError:
        pass  # Completely eliminated from the filesystem

    packages_to_check = ["zylar", "api", "agents"]
    imported_modules = []

    for pkg_name in packages_to_check:
        try:
            pkg = importlib.import_module(pkg_name)
            imported_modules.append(pkg)
            if hasattr(pkg, "__path__"):
                for _, mod_name, _ in pkgutil.walk_packages(pkg.__path__, prefix=f"{pkg_name}."):
                    try:
                        imported_modules.append(importlib.import_module(mod_name))
                    except Exception:
                        pass
        except Exception:
            pass

    for mod in imported_modules:
        mod_dict = getattr(mod, "__dict__", {})
        for name, val in mod_dict.items():
            val_str = str(val).lower()
            assert "sqlite_manager" not in val_str, (
                f"Module {mod.__name__} has reference to sqlite_manager in symbol {name}"
            )


def test_validation_exception_handler_scrubs_raw_input():
    """Verifies that 422 RequestValidationError details do not echo back raw sensitive user input."""
    sensitive_input = "MySuperSecretPlaintextPassword!999"
    # Pass integer where string expected to trigger a type error
    response = client.post(
        "/api/auth/token",
        json={"username": "alice", "password": {"secret_obj": sensitive_input}},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "Validation Error"
    details = data["details"]
    assert isinstance(details, list)
    for err in details:
        # Crucial: input must be scrubbed
        assert "input" not in err, f"Error detail leaked raw input: {err}"
    assert sensitive_input not in response.text


def test_login_throttler_blocks_abusive_logins():
    """Verifies that repeated failed login attempts trigger HTTP 429 Too Many Requests."""
    from zylar.core.security import get_login_throttler

    throttler = get_login_throttler()
    throttler.reset()

    try:
        # Send 5 invalid login attempts
        for _ in range(5):
            res = client.post(
                "/api/auth/token",
                json={"username": "throttled_attacker", "password": "wrong_password_attempt"},
            )
            assert res.status_code == 401

        # 6th attempt must be throttled with HTTP 429
        res_locked = client.post(
            "/api/auth/token",
            json={"username": "throttled_attacker", "password": "wrong_password_attempt"},
        )
        assert res_locked.status_code == 429
        data = res_locked.json()
        assert "Too many failed authentication attempts" in data["error"]
        assert "Retry-After" in res_locked.headers
    finally:
        throttler.reset()


def test_ingestion_status_masks_raw_internal_exception():
    """Verifies that /api/ingestion/status redacts passwords from checkpoint last_error."""
    from unittest.mock import MagicMock, patch

    from zylar.core.security import Role, create_access_token
    from zylar.persistence.models import IngestionCheckpointModel

    raw_error = (
        "Connection failed to postgresql://zylar_user:super_secret_db_pass@127.0.0.1:5432/zylar_db"
    )
    mock_cp = IngestionCheckpointModel(
        stream_id="elasticsearch-soc-events",
        status="RETRYING",
        last_processed_timestamp=datetime(2026, 10, 28, 12, 0, tzinfo=UTC),
        last_processed_id="doc-123",
        batch_sequence=1,
        events_processed_count=10,
        retry_count=2,
        last_error=raw_error,
    )

    token = create_access_token("analyst_test", role=Role.ANALYST)
    headers = {"Authorization": f"Bearer {token}"}

    with patch("api.main.UnitOfWork") as mock_uow_cls:
        mock_uow = MagicMock()
        mock_uow.checkpoints.get.return_value = mock_cp
        mock_uow.checkpoints.get_checkpoint_lag_seconds.return_value = 15.0
        mock_uow.checkpoints.get_dead_letter_count.return_value = 0
        mock_uow_cls.return_value.__enter__.return_value = mock_uow

        res = client.get("/api/ingestion/status", headers=headers)

    assert res.status_code == 200
    data = res.json()
    assert "super_secret_db_pass" not in res.text
    assert "super_secret_db_pass" not in data.get("last_error", "")
    assert "postgresql://zylar_user:***@127.0.0.1:5432/zylar_db" in data["last_error"]


def test_trusted_proxy_client_ip_resolution():
    from unittest.mock import MagicMock

    from api.main import get_client_ip

    mock_req = MagicMock()
    mock_req.client.host = "127.0.0.1"  # in trusted_proxies
    mock_req.headers.get.return_value = "203.0.113.195, 127.0.0.1"

    resolved_ip = get_client_ip(mock_req)
    assert resolved_ip == "203.0.113.195"


def test_untrusted_proxy_ignores_forwarded_for():
    from unittest.mock import MagicMock

    from api.main import get_client_ip

    mock_req = MagicMock()
    mock_req.client.host = "198.51.100.5"  # not in trusted_proxies
    mock_req.headers.get.return_value = "10.0.0.1"

    resolved_ip = get_client_ip(mock_req)
    assert resolved_ip == "198.51.100.5"
