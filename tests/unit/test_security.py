from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from zylar.core.security import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    Role,
    UserPrincipal,
    UserStore,
    create_access_token,
    decode_access_token,
    hash_password,
    require_roles,
    verify_password,
)


def test_password_hashing_and_verification():
    raw_pass = "SuperSecretSecurePass123!"
    hashed = hash_password(raw_pass)

    assert hashed != raw_pass
    assert hashed.startswith("$2b$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw_pass, "") is False

    with pytest.raises(ValueError):
        hash_password("")


def test_user_principal_immutability_and_validation():
    principal = UserPrincipal(subject="alice", role=Role.ANALYST)
    assert principal.subject == "alice"
    assert principal.role == Role.ANALYST

    # Frozen model cannot be mutated
    with pytest.raises(ValidationError):
        principal.subject = "bob"

    # Invalid role rejected
    with pytest.raises(ValidationError):
        UserPrincipal(subject="charlie", role="superuser")  # type: ignore[arg-type]


def test_token_creation_and_decoding():
    token = create_access_token(subject="alice", role=Role.ANALYST)
    principal = decode_access_token(token)

    assert principal.subject == "alice"
    assert principal.role == Role.ANALYST


def test_token_expiration_rejected():
    # Create token expired 10 minutes ago
    expired_delta = timedelta(minutes=-10)
    token = create_access_token(subject="bob", role=Role.VIEWER, expires_delta=expired_delta)

    with pytest.raises(HTTPException) as exc:
        decode_access_token(token)
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()


def test_token_issuer_audience_validation():
    # Craft token with invalid issuer
    now = datetime.now(UTC)
    invalid_payload = {
        "sub": "mallory",
        "role": "admin",
        "iss": "rogue-issuer",
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    from zylar.core.settings import get_settings

    secret = get_settings().auth_signing_key.get_secret_value()
    rogue_token = jwt.encode(invalid_payload, secret, algorithm=JWT_ALGORITHM)

    with pytest.raises(HTTPException) as exc:
        decode_access_token(rogue_token)
    assert exc.value.status_code == 401
    assert "invalid" in exc.value.detail.lower() or "issuer" in exc.value.detail.lower()


def test_token_tampering_rejected():
    token = create_access_token(subject="alice", role=Role.ANALYST)
    tampered = token[:-4] + "wxyz"

    with pytest.raises(HTTPException) as exc:
        decode_access_token(tampered)
    assert exc.value.status_code == 401


def test_user_store_bootstrap_and_authentication():
    from zylar.core.settings import get_settings

    settings = get_settings()
    store = UserStore()
    # Bootstrap admin should exist
    admin_principal = store.authenticate(
        settings.bootstrap_admin_username,
        settings.bootstrap_admin_password.get_secret_value(),
    )
    assert admin_principal is not None
    assert admin_principal.subject == settings.bootstrap_admin_username
    assert admin_principal.role == Role.ADMIN

    # Non-existent user
    assert store.authenticate("nobody", "password") is None

    # Bad password
    assert store.authenticate("admin", "wrong-password") is None


def test_user_store_user_provisioning_lifecycle():
    import uuid

    store = UserStore()
    username = f"analyst_bob_{uuid.uuid4().hex[:8]}"

    # Create new analyst user
    analyst_record = store.create_user(
        username=username,
        password="BobSecurePassword2026!",
        role=Role.ANALYST,
    )
    assert analyst_record.username == username
    assert analyst_record.role == Role.ANALYST

    # Authenticate newly created user
    bob_principal = store.authenticate(username, "BobSecurePassword2026!")
    assert bob_principal is not None
    assert bob_principal.role == Role.ANALYST

    # Cannot create duplicate username
    with pytest.raises(ValueError) as exc:
        store.create_user(username, "AnotherPass", Role.ANALYST)
    assert "already exists" in str(exc.value)

    # Disabled user cannot authenticate
    store.disable_user(username)
    assert store.authenticate(username, "BobSecurePassword2026!") is None


def test_require_roles_dependency():
    admin_principal = UserPrincipal(subject="admin", role=Role.ADMIN)
    analyst_principal = UserPrincipal(subject="bob", role=Role.ANALYST)
    viewer_principal = UserPrincipal(subject="charlie", role=Role.VIEWER)

    # Dependency requiring Analyst or Admin
    analyst_or_admin = require_roles(Role.ANALYST, Role.ADMIN)

    # Analyst allowed
    res_analyst = analyst_or_admin(principal=analyst_principal)
    assert res_analyst == analyst_principal

    # Admin allowed
    res_admin = analyst_or_admin(principal=admin_principal)
    assert res_admin == admin_principal

    # Viewer forbidden (HTTP 403)
    with pytest.raises(HTTPException) as exc:
        analyst_or_admin(principal=viewer_principal)
    assert exc.value.status_code == 403
    assert "Forbidden" in exc.value.detail


def test_require_roles_admin_only_dependency():
    admin_principal = UserPrincipal(subject="admin", role=Role.ADMIN)
    analyst_principal = UserPrincipal(subject="bob", role=Role.ANALYST)

    admin_only = require_roles(Role.ADMIN)

    assert admin_only(principal=admin_principal) == admin_principal

    with pytest.raises(HTTPException) as exc:
        admin_only(principal=analyst_principal)
    assert exc.value.status_code == 403


def test_sanitize_audit_details_redacts_sensitive_keys():
    from zylar.core.security import sanitize_audit_details

    data = {
        "username": "admin",
        "password": "super-secret-password-123",
        "token": "jwt-token-xyz",
        "api_key": "sk-123456789",
        "nested": {
            "secret_key": "private-key-material",
            "safe_field": "public_data",
            "authorization": "Bearer secret-token",
        },
        "items": [
            {"credential": "secret-credential", "name": "service-account"},
            "safe string in list",
        ],
    }

    sanitized = sanitize_audit_details(data)
    assert sanitized["username"] == "admin"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["secret_key"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == "public_data"
    assert sanitized["nested"]["authorization"] == "[REDACTED]"
    assert sanitized["items"][0]["credential"] == "[REDACTED]"
    assert sanitized["items"][0]["name"] == "service-account"
    assert sanitized["items"][1] == "safe string in list"


def test_sanitize_audit_details_redacts_embedded_secrets():
    from zylar.core.security import sanitize_audit_details

    conn_str = "postgresql+psycopg://app_user:ultra_secret_pass_999@db.internal:5432/zylar_db"
    bearer_str = "Connecting with Authorization: Bearer abc123def456xyz and key=secret_val"

    sanitized_conn = sanitize_audit_details(conn_str)
    assert "ultra_secret_pass_999" not in sanitized_conn
    assert "postgresql+psycopg://app_user:***@db.internal:5432/zylar_db" == sanitized_conn

    sanitized_bearer = sanitize_audit_details(bearer_str)
    assert "abc123def456xyz" not in sanitized_bearer
    assert "Bearer [REDACTED]" in sanitized_bearer


def test_sanitize_audit_details_truncates_long_strings_and_bounds_depth():
    from zylar.core.security import sanitize_audit_details

    long_str = "A" * 2000
    sanitized_str = sanitize_audit_details(long_str, max_str_len=100)
    assert len(sanitized_str) == 100
    assert sanitized_str.endswith("...[TRUNCATED]")

    # Deeply nested dict
    deep_dict: dict[str, Any] = {"level": 0}
    curr = deep_dict
    for i in range(1, 10):
        curr["next"] = {"level": i}
        curr = curr["next"]

    sanitized_deep = sanitize_audit_details(deep_dict, max_depth=3)
    # Beyond max_depth, nested dict is replaced by [DEPTH_EXCEEDED]
    assert sanitized_deep["next"]["next"]["next"] == "[DEPTH_EXCEEDED]"


def test_login_throttler_locks_out_after_threshold_and_recovers():
    from zylar.core.security import LoginThrottler

    throttler = LoginThrottler(max_attempts=3, window_seconds=60, lockout_seconds=300)
    key = "ip:198.51.100.1"

    assert throttler.is_locked(key) is False

    # 1st and 2nd failed attempt: not locked
    throttler.record_failure(key)
    assert throttler.is_locked(key) is False
    throttler.record_failure(key)
    assert throttler.is_locked(key) is False

    # 3rd failed attempt: threshold reached -> locked out!
    throttler.record_failure(key)
    assert throttler.is_locked(key) is True

    with pytest.raises(HTTPException) as exc:
        throttler.check_rate_limit(key)
    assert exc.value.status_code == 429
    assert "Too many failed" in exc.value.detail

    # Record success clears lockout
    throttler.record_success(key)
    assert throttler.is_locked(key) is False


def test_login_throttler_independent_keys():
    from zylar.core.security import LoginThrottler

    throttler = LoginThrottler(max_attempts=2, window_seconds=60, lockout_seconds=300)
    throttler.record_failure("user:alice")
    throttler.record_failure("user:alice")

    assert throttler.is_locked("user:alice") is True
    assert throttler.is_locked("user:bob") is False


def test_dashboard_escape_dot_identifier():
    from dashboard.app import escape_dot_identifier

    # Escape quotes
    assert escape_dot_identifier('User:"admin"') == 'User:\\"admin\\"'
    # Escape backslashes
    assert escape_dot_identifier("Path\\to\\file") == "Path\\\\to\\\\file"
    # Escape newlines
    assert escape_dot_identifier("Node\nwith\rnewline") == "Node\\nwith\\rnewline"
    # Empty
    assert escape_dot_identifier("") == ""


def test_login_throttler_thread_safety_concurrency():
    import concurrent.futures

    from zylar.core.security import LoginThrottler

    throttler = LoginThrottler(max_attempts=10, window_seconds=60, lockout_seconds=300)
    key = "ip:10.0.0.99"

    def attempt_failure():
        throttler.record_failure(key)

    # Concurrently execute 30 failures across 10 threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_failure) for _ in range(30)]
        concurrent.futures.wait(futures)

    # After 30 attempts, throttler must be safely locked
    assert throttler.is_locked(key) is True
    assert len(throttler._failures.get(key, [])) == 30


def test_login_throttler_capacity_bounding():
    from zylar.core.security import LoginThrottler

    # Capacity set to 10 keys
    throttler = LoginThrottler(max_attempts=5, window_seconds=1, lockout_seconds=2, max_tracked_keys=10)

    for i in range(25):
        throttler.record_failure(f"user:user_{i}")

    # Tracked keys must be bounded around max_tracked_keys
    assert len(throttler._failures) <= 15


def test_user_store_with_database_session_factory():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from zylar.core.security import Role, UserStore, reset_user_store
    from zylar.core.settings import get_settings
    from zylar.persistence.models import Base

    settings = get_settings()
    reset_user_store()
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["users"]])
    session_factory = sessionmaker(bind=engine)

    store = UserStore(session_factory=session_factory)

    # Admin is automatically bootstrapped into DB using configured settings
    admin = store.authenticate(
        settings.bootstrap_admin_username,
        settings.bootstrap_admin_password.get_secret_value(),
    )
    assert admin is not None
    assert admin.role == Role.ADMIN

    # Create new analyst user via store backed by DB
    user = store.create_user("analyst_durable", "pass123456", Role.ANALYST)
    assert user.username == "analyst_durable"

    # Authenticate via DB
    principal = store.authenticate("analyst_durable", "pass123456")
    assert principal is not None
    assert principal.role == Role.ANALYST

    # Disable user via DB
    store.disable_user("analyst_durable")
    assert store.authenticate("analyst_durable", "pass123456") is None

    # Duplicate username raises ValueError
    with pytest.raises(ValueError):
        store.create_user("analyst_durable", "anotherpass", Role.ANALYST)

    Base.metadata.drop_all(engine, tables=[Base.metadata.tables["users"]])
    engine.dispose()
    reset_user_store()


def test_user_store_production_fails_closed_without_database(monkeypatch: pytest.MonkeyPatch):
    from unittest.mock import MagicMock

    from sqlalchemy.exc import OperationalError

    from zylar.core.security import UserStore, reset_user_store
    from zylar.core.settings import get_settings
    from zylar.persistence.database import reset_database_manager

    reset_user_store()
    reset_database_manager()
    monkeypatch.setenv("ZYLAR_ENVIRONMENT", "production")
    monkeypatch.setenv("ZYLAR_AUTH_SIGNING_KEY", "prod_signing_key_at_least_32_characters_long_for_test")
    monkeypatch.setenv("ZYLAR_BOOTSTRAP_ADMIN_PASSWORD", "SuperSecureAdminPassword123!")
    monkeypatch.setenv("ZYLAR_ELASTICSEARCH_URL", "https://synthetic.internal:9200")
    monkeypatch.setenv("ZYLAR_ELASTICSEARCH_USERNAME", "elastic_admin")
    monkeypatch.setenv("ZYLAR_ELASTICSEARCH_PASSWORD", "elastic_pass_123456")
    get_settings.cache_clear()

    # Case 1: get_database_manager fails during initialization
    failing_db_manager = MagicMock(side_effect=RuntimeError("Cannot connect to DB cluster"))
    monkeypatch.setattr("zylar.persistence.database.get_database_manager", failing_db_manager)

    try:
        with pytest.raises(RuntimeError) as exc_info:
            UserStore()
        assert "in-memory fallback is strictly forbidden" in str(exc_info.value)
    finally:
        reset_user_store()

    # Case 2: session_factory raises OperationalError during admin bootstrap
    mock_session = MagicMock()
    mock_session.begin.side_effect = OperationalError("connection refused", params=None, orig=Exception("refused"))
    mock_factory = MagicMock(return_value=mock_session)
    mock_session.__enter__.return_value = mock_session

    try:
        with pytest.raises(RuntimeError) as exc_info:
            UserStore(session_factory=mock_factory)
        assert "Failed to bootstrap administrator account into PostgreSQL" in str(exc_info.value)
    finally:
        get_settings.cache_clear()
        reset_user_store()
        reset_database_manager()


