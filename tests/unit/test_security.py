from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
        principal.subject = "bob"  # type: ignore[misc]

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
    store = UserStore()
    # Bootstrap admin should exist
    admin_principal = store.authenticate("admin", "change-admin-password-in-production")
    assert admin_principal is not None
    assert admin_principal.subject == "admin"
    assert admin_principal.role == Role.ADMIN

    # Non-existent user
    assert store.authenticate("nobody", "password") is None

    # Bad password
    assert store.authenticate("admin", "wrong-password") is None


def test_user_store_user_provisioning_lifecycle():
    store = UserStore()

    # Create new analyst user
    analyst_record = store.create_user(
        username="analyst_bob",
        password="BobSecurePassword2026!",
        role=Role.ANALYST,
    )
    assert analyst_record.username == "analyst_bob"
    assert analyst_record.role == Role.ANALYST

    # Authenticate newly created user
    bob_principal = store.authenticate("analyst_bob", "BobSecurePassword2026!")
    assert bob_principal is not None
    assert bob_principal.role == Role.ANALYST

    # Cannot create duplicate username
    with pytest.raises(ValueError) as exc:
        store.create_user("analyst_bob", "AnotherPass", Role.ANALYST)
    assert "already exists" in str(exc.value)

    # Disabled user cannot authenticate
    store.disable_user("analyst_bob")
    assert store.authenticate("analyst_bob", "BobSecurePassword2026!") is None


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
