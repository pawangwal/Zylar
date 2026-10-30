from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

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

    subject: str = Field(
        ..., min_length=1, max_length=128, description="Authenticated subject identity"
    )
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
    """Trusted identity source backed by PostgreSQL with transactional advisory lock bootstrap."""

    def __init__(self, session_factory: sessionmaker[Session] | None = None) -> None:
        settings = get_settings()
        self._session_factory = session_factory
        if self._session_factory is None:
            if settings.environment == "production":
                try:
                    from zylar.persistence.database import get_database_manager

                    self._session_factory = get_database_manager().session_factory
                except Exception as exc:
                    raise RuntimeError(
                        "Production mode requires an authoritative PostgreSQL identity store; "
                        "in-memory fallback is strictly forbidden."
                    ) from exc
            else:
                try:
                    from zylar.persistence.database import get_database_manager

                    self._session_factory = get_database_manager().session_factory
                except Exception:
                    self._session_factory = None

        self._in_memory_users: dict[str, UserRecord] = {}
        self._bootstrap_admin()

    def _bootstrap_admin(self) -> None:
        settings = get_settings()
        admin_username = settings.bootstrap_admin_username
        admin_password = settings.bootstrap_admin_password.get_secret_value()

        if self._session_factory is not None:
            try:
                from sqlalchemy import text

                from zylar.persistence.repositories import UserRepository

                with self._session_factory() as session:
                    with session.begin():
                        if session.bind is not None and session.bind.dialect.name == "postgresql":
                            session.execute(text("SELECT pg_advisory_xact_lock(742109)"))
                        repo = UserRepository(session)
                        existing = repo.get_by_username(admin_username)
                        if existing is None:
                            repo.create_user(
                                username=admin_username,
                                hashed_password=hash_password(admin_password),
                                role="admin",
                                disabled=False,
                            )
                            logger.info(
                                "Bootstrapped initial administrator account into PostgreSQL: %s",
                                admin_username,
                            )
            except Exception as exc:
                if settings.environment == "production":
                    raise RuntimeError(
                        "Failed to bootstrap administrator account into PostgreSQL"
                    ) from exc
                logger.warning(
                    "Database admin bootstrap failed, falling back to memory in development: %s", exc
                )
                self._session_factory = None
                self._bootstrap_admin_in_memory(admin_username, admin_password)
        else:
            if settings.environment == "production":
                raise RuntimeError(
                    "Production mode requires an authoritative PostgreSQL identity store; "
                    "in-memory fallback is strictly forbidden."
                )
            self._bootstrap_admin_in_memory(admin_username, admin_password)

    def _bootstrap_admin_in_memory(self, admin_username: str, admin_password: str) -> None:
        if admin_username not in self._in_memory_users:
            self._in_memory_users[admin_username] = UserRecord(
                username=admin_username,
                hashed_password=hash_password(admin_password),
                role=Role.ADMIN,
                disabled=False,
            )
            logger.info("Bootstrapped initial administrator account in memory: %s", admin_username)

    def authenticate(self, username: str, plain_password: str) -> UserPrincipal | None:
        """Verifies credentials against the trusted user store.

        Clients cannot request or choose their role; the role is authoritatively
        assigned from the server-side identity store.
        """
        if self._session_factory is not None:
            from zylar.persistence.repositories import UserRepository

            with self._session_factory() as session:
                repo = UserRepository(session)
                user = repo.get_by_username(username)
                if not user or user.disabled:
                    return None
                if not verify_password(plain_password, user.hashed_password):
                    return None
                return UserPrincipal(subject=user.username, role=Role(user.role))
        else:
            user_rec = self._in_memory_users.get(username)
            if not user_rec or user_rec.disabled:
                return None
            if not verify_password(plain_password, user_rec.hashed_password):
                return None
            return UserPrincipal(subject=user_rec.username, role=user_rec.role)

    def create_user(self, username: str, password: str, role: Role) -> UserRecord:
        """Provisions a new user in the identity store with a hashed credential."""
        clean_user = username.strip() if username else ""
        if not clean_user:
            raise ValueError("Username must not be empty")

        if self._session_factory is not None:
            from zylar.persistence.exceptions import ConstraintViolationError
            from zylar.persistence.repositories import UserRepository

            hashed = hash_password(password)
            with self._session_factory() as session:
                with session.begin():
                    repo = UserRepository(session)
                    try:
                        user = repo.create_user(
                            username=clean_user,
                            hashed_password=hashed,
                            role=str(role).lower(),
                            disabled=False,
                        )
                        return UserRecord(
                            username=user.username,
                            hashed_password=user.hashed_password,
                            role=Role(user.role),
                            disabled=user.disabled,
                        )
                    except ConstraintViolationError as exc:
                        raise ValueError(str(exc)) from exc
        else:
            if clean_user in self._in_memory_users:
                raise ValueError(f"User '{clean_user}' already exists")
            record = UserRecord(
                username=clean_user,
                hashed_password=hash_password(password),
                role=role,
                disabled=False,
            )
            self._in_memory_users[clean_user] = record
            return record

    def disable_user(self, username: str) -> None:
        """Disables a user account, preventing further authentications."""
        if self._session_factory is not None:
            from zylar.persistence.repositories import UserRepository

            with self._session_factory() as session:
                with session.begin():
                    repo = UserRepository(session)
                    user = repo.get_by_username(username)
                    if user is not None:
                        repo.update_disabled(user.id, True)
        else:
            if username in self._in_memory_users:
                self._in_memory_users[username].disabled = True

    def get_user(self, username: str) -> UserRecord | None:
        """Retrieves a user record by username."""
        if self._session_factory is not None:
            from zylar.persistence.repositories import UserRepository

            with self._session_factory() as session:
                repo = UserRepository(session)
                user = repo.get_by_username(username)
                if user is None:
                    return None
                return UserRecord(
                    username=user.username,
                    hashed_password=user.hashed_password,
                    role=Role(user.role),
                    disabled=user.disabled,
                )
        else:
            return self._in_memory_users.get(username)


# Process-wide singleton user store
_user_store: UserStore | None = None


def get_user_store(session_factory: sessionmaker[Session] | None = None) -> UserStore:
    """Returns the process-wide trusted identity store."""
    global _user_store
    if _user_store is None:
        _user_store = UserStore(session_factory=session_factory)
    elif session_factory is not None and _user_store._session_factory != session_factory:
        _user_store = UserStore(session_factory=session_factory)
    return _user_store


def reset_user_store() -> None:
    """Resets the process-wide user store singleton (primarily for tests)."""
    global _user_store
    _user_store = None


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


_URL_PASSWORD_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:)([^@]+)(@)")
_BEARER_TOKEN_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", re.IGNORECASE)
_KV_SECRET_RE = re.compile(
    r"((?:password|passwd|secret|token|api_?key)\s*[=:]\s*)[^\s,;&]+", re.IGNORECASE
)


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[_\-\s]", "", str(key)).lower()
    return any(
        p in normalized
        for p in (
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "credential",
            "privatekey",
            "authorization",
        )
    )


def _sanitize_string(s: str, max_str_len: int = 1024) -> str:
    redacted = _URL_PASSWORD_RE.sub(r"\1***\3", s)
    redacted = _BEARER_TOKEN_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _KV_SECRET_RE.sub(r"\1[REDACTED]", redacted)
    suffix = "...[TRUNCATED]"
    if len(redacted) > max_str_len:
        prefix_len = max(0, max_str_len - len(suffix))
        return redacted[:prefix_len] + suffix
    return redacted


def sanitize_audit_details(
    data: Any,
    max_depth: int = 5,
    max_str_len: int = 1024,
    current_depth: int = 0,
) -> Any:
    """Recursively sanitizes data structures to prevent secret leakage in audit logs.

    Redacts credentials, API keys, tokens, and passwords in keys and strings,
    truncates oversized string values, and bounds maximum recursion depth.
    """
    if current_depth >= max_depth:
        return "[DEPTH_EXCEEDED]"

    if isinstance(data, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in data.items():
            str_k = str(k)
            if _is_sensitive_key(str_k):
                sanitized_dict[str_k] = "[REDACTED]"
            else:
                sanitized_dict[str_k] = sanitize_audit_details(
                    v,
                    max_depth=max_depth,
                    max_str_len=max_str_len,
                    current_depth=current_depth + 1,
                )
        return sanitized_dict

    if isinstance(data, (list, tuple, set)):
        items = [
            sanitize_audit_details(
                item,
                max_depth=max_depth,
                max_str_len=max_str_len,
                current_depth=current_depth + 1,
            )
            for item in data
        ]
        return items if isinstance(data, list) else type(data)(items)

    if isinstance(data, str):
        return _sanitize_string(data, max_str_len=max_str_len)

    if hasattr(data, "model_dump") and callable(data.model_dump):
        return sanitize_audit_details(
            data.model_dump(mode="json"),
            max_depth=max_depth,
            max_str_len=max_str_len,
            current_depth=current_depth,
        )

    return data


class LoginThrottler:
    """Thread-safe in-memory rate limiter and lockout mechanism for authentication attempts.

    Enforces maximum failed attempts per IP address and per username over a sliding window.
    Protects internal state with a reentrant lock and bounds tracked keys to prevent memory exhaustion.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
        max_tracked_keys: int = 10_000,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_tracked_keys = max_tracked_keys
        self._lock = threading.RLock()
        self._failures: dict[str, list[datetime]] = {}
        self._lockouts: dict[str, datetime] = {}

    def _prune_expired_locked(self, now: datetime) -> None:
        """Internal helper to prune expired lockout and failure entries while holding the lock."""
        cutoff = now - timedelta(seconds=self.window_seconds)

        # 1. Prune expired lockouts
        expired_lockouts = [k for k, exp in self._lockouts.items() if exp <= now]
        for k in expired_lockouts:
            del self._lockouts[k]
            self._failures.pop(k, None)

        # 2. Prune expired failures
        empty_keys = []
        for k, timestamps in self._failures.items():
            valid = [t for t in timestamps if t > cutoff]
            if not valid:
                empty_keys.append(k)
            else:
                self._failures[k] = valid
        for k in empty_keys:
            del self._failures[k]

        # 3. If still oversized, evict oldest entries
        if len(self._failures) > self.max_tracked_keys:
            excess = len(self._failures) - self.max_tracked_keys
            for k in list(self._failures.keys())[:excess]:
                del self._failures[k]
                self._lockouts.pop(k, None)

    def is_locked(self, key: str) -> bool:
        """Returns True if the key is currently locked out."""
        with self._lock:
            now = datetime.now(UTC)
            locked_until = self._lockouts.get(key)
            if locked_until is not None:
                if now < locked_until:
                    return True
                del self._lockouts[key]
                self._failures.pop(key, None)
            return False

    def check_rate_limit(self, key: str) -> None:
        """Raises HTTP 429 if the key is currently locked out."""
        with self._lock:
            if self.is_locked(key):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed authentication attempts. Please try again later.",
                    headers={"Retry-After": str(self.lockout_seconds)},
                )

    def record_failure(self, key: str) -> None:
        """Records a failed authentication attempt, locking out if threshold exceeded."""
        with self._lock:
            now = datetime.now(UTC)
            cutoff = now - timedelta(seconds=self.window_seconds)
            attempts = [t for t in self._failures.get(key, []) if t > cutoff]
            attempts.append(now)
            self._failures[key] = attempts

            if len(attempts) >= self.max_attempts:
                self._lockouts[key] = now + timedelta(seconds=self.lockout_seconds)
                logger.warning(
                    "Authentication key '%s' locked out for %d seconds after %d failed attempts",
                    key,
                    self.lockout_seconds,
                    len(attempts),
                )

            # Prune if tracking many keys to prevent unbounded memory growth
            if len(self._failures) > self.max_tracked_keys // 2:
                self._prune_expired_locked(now)

    def record_success(self, key: str) -> None:
        """Clears failures and lockouts upon successful authentication."""
        with self._lock:
            self._failures.pop(key, None)
            self._lockouts.pop(key, None)

    def reset(self) -> None:
        """Clears all stored failures and lockouts (useful for test resets)."""
        with self._lock:
            self._failures.clear()
            self._lockouts.clear()


_login_throttler: LoginThrottler | None = None


def get_login_throttler() -> LoginThrottler:
    """Returns the process-wide login throttler instance."""
    global _login_throttler
    if _login_throttler is None:
        _login_throttler = LoginThrottler()
    return _login_throttler
