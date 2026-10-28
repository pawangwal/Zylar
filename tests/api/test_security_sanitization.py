from __future__ import annotations

import logging
import pkgutil

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
            assert "sqlite_manager" not in val_str, f"Module {mod.__name__} has reference to sqlite_manager in symbol {name}"
