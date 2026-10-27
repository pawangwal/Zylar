from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from zylar.core.settings import get_settings

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "zylar"
JWT_AUDIENCE = "zylar-api"

bearer_scheme = HTTPBearer(auto_error=False)


class Role(StrEnum):
    """Supported authorization roles."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserPrincipal(BaseModel):
    """Immutable typed principal representing an authenticated entity and role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(..., min_length=1, max_length=128, description="Authenticated subject identity")
    role: Role = Field(..., description="Authorized role")


class UserRecord(BaseModel):
    """Server-side record in the trusted identity source."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=128)
    hashed_password: str = Field(..., min_length=1)
    role: Role
    disabled: bool = False


def hash_password(password: str) -> str:
    """Hashes a plain password using bcrypt with a secure cost factor."""
    if not password:
        raise ValueError("Password must not be empty")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash in constant time."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(
    subject: str,
    role: Role | str,
    expires_delta: timedelta | None = None,
) -> str:
    """Creates a signed, time-bounded JWT carrying the authenticated subject and role."""
    settings = get_settings()
    now = datetime.now(UTC)

    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.token_expire_minutes)

    payload: dict[str, Any] = {
        "sub": subject,
        "role": str(role),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    secret = settings.auth_signing_key.get_secret_value()
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> UserPrincipal:
    """Validates and decodes a signed access token, returning the typed UserPrincipal."""
    settings = get_settings()
    secret = settings.auth_signing_key.get_secret_value()

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    subject = payload.get("sub")
    role_str = payload.get("role")
    if not subject or not role_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing required claims",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        role = Role(role_str)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token contains unrecognized role",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return UserPrincipal(subject=subject, role=role)


class UserStore:
    """Trusted in-memory identity source with secure administrator bootstrap."""

    def __init__(self) -> None:
        self._users: dict[str, UserRecord] = {}
        self._bootstrap_admin()

    def _bootstrap_admin(self) -> None:
        settings = get_settings()
        admin_username = settings.bootstrap_admin_username
        admin_password = settings.bootstrap_admin_password.get_secret_value()

        if admin_username not in self._users:
            self._users[admin_username] = UserRecord(
                username=admin_username,
                hashed_password=hash_password(admin_password),
                role=Role.ADMIN,
                disabled=False,
            )
            logger.info("Bootstrapped initial administrator account: %s", admin_username)

    def authenticate(self, username: str, plain_password: str) -> UserPrincipal | None:
        """Verifies credentials against the trusted user store.

        Clients cannot request or choose their role; the role is authoritatively
        assigned from the server-side identity store.
        """
        user = self._users.get(username)
        if not user or user.disabled:
            return None

        if not verify_password(plain_password, user.hashed_password):
            return None

        return UserPrincipal(subject=user.username, role=user.role)

    def create_user(self, username: str, password: str, role: Role) -> UserRecord:
        """Provisions a new user in the identity store with a hashed credential."""
        if not username or not username.strip():
            raise ValueError("Username must not be empty")
        if username in self._users:
            raise ValueError(f"User '{username}' already exists")

        record = UserRecord(
            username=username.strip(),
            hashed_password=hash_password(password),
            role=role,
            disabled=False,
        )
        self._users[username] = record
        return record

    def disable_user(self, username: str) -> None:
        """Disables a user account, preventing further authentications."""
        if username in self._users:
            self._users[username].disabled = True

    def get_user(self, username: str) -> UserRecord | None:
        """Retrieves a user record by username."""
        return self._users.get(username)


# Process-wide singleton user store
_user_store: UserStore | None = None


def get_user_store() -> UserStore:
    """Returns the process-wide trusted identity store."""
    global _user_store
    if _user_store is None:
        _user_store = UserStore()
    return _user_store


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)] = None,
) -> UserPrincipal:
    """FastAPI dependency to extract and authenticate the current UserPrincipal from a Bearer token."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return decode_access_token(credentials.credentials)


def require_roles(*allowed_roles: Role | str) -> Callable[..., UserPrincipal]:
    """Dependency factory enforcing Role-Based Access Control (RBAC).

    Returns a FastAPI dependency that verifies the authenticated principal holds
    one of the allowed roles. Prohibited roles receive HTTP 403 Forbidden.
    """
    allowed: set[str] = {str(r) for r in allowed_roles}

    def role_checker(
        principal: Annotated[UserPrincipal, Depends(get_current_user)],
    ) -> UserPrincipal:
        if str(principal.role) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: role '{principal.role}' is not authorized for this resource",
            )
        return principal

    return role_checker
