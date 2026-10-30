from __future__ import annotations

import re
import threading
import urllib.parse
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from zylar.core.settings import Settings, get_settings
from zylar.persistence.exceptions import (
    DatabaseConfigurationError,
    DatabaseConnectionError,
)


def sanitize_db_url(url: str) -> str:
    """Masks database passwords and sensitive components from URLs."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.password:
            user = parsed.username or ""
            host = parsed.hostname or ""
            port_str = f":{parsed.port}" if parsed.port else ""
            netloc = f"{user}:***@{host}{port_str}"
            return urllib.parse.urlunsplit(
                (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
            )
        return url
    except Exception:
        return "[redacted-database-url]"


def sanitize_error_message(exc: Exception, raw_url: str | None = None) -> str:
    """Strips database credentials and passwords from exception messages."""
    msg = str(exc)
    if raw_url:
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            if parsed.password:
                msg = msg.replace(parsed.password, "***")
        except Exception:
            pass
    return re.sub(r":([^/@:]+)@", ":***@", msg)


class DatabaseManager:
    """Manages SQLAlchemy 2.x Engine and Session factory for PostgreSQL persistence.

    Enforces explicit pool configuration, pre-ping connection liveness checks,
    credential sanitization, and deterministic engine disposal.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        pool_size: int | None = None,
        max_overflow: int | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._pool_size = pool_size if pool_size is not None else self._settings.db_pool_size
        self._max_overflow = (
            max_overflow if max_overflow is not None else self._settings.db_max_overflow
        )
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None
        self._lock = threading.RLock()

    @property
    def engine(self) -> Engine:
        """Returns the lazily initialized SQLAlchemy Engine."""
        if self._engine is None:
            with self._lock:
                if self._engine is None:
                    self._engine = self._create_engine()
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Returns the sessionmaker configured with expire_on_commit=False."""
        if self._session_factory is None:
            with self._lock:
                if self._session_factory is None:
                    engine = self.engine
                    self._session_factory = sessionmaker(
                        bind=engine,
                        expire_on_commit=False,
                        autoflush=False,
                    )
        return self._session_factory

    def _create_engine(self) -> Engine:
        raw_url = str(self._settings.database_url)
        try:
            parsed = urllib.parse.urlsplit(raw_url)
        except Exception as exc:
            raise DatabaseConfigurationError(
                f"Invalid database URL: {sanitize_db_url(raw_url)}"
            ) from exc

        scheme = parsed.scheme.lower()
        if not (scheme == "postgresql" or scheme.startswith("postgresql+")):
            raise DatabaseConfigurationError(
                f"Unsupported database scheme '{scheme}'. Only PostgreSQL is supported; "
                "no silent fallback to other engines is permitted."
            )

        try:
            return create_engine(
                raw_url,
                pool_size=self._pool_size,
                max_overflow=self._max_overflow,
                pool_timeout=self._settings.db_pool_timeout_seconds,
                pool_recycle=self._settings.db_pool_recycle_seconds,
                pool_pre_ping=self._settings.db_pool_pre_ping,
            )
        except Exception as exc:
            sanitized = sanitize_error_message(exc, raw_url)
            raise DatabaseConnectionError(
                f"Failed to create database engine for {self._settings.redacted_database_url}: {sanitized}"
            ) from None

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Provides a managed SQLAlchemy session with guaranteed rollback on error and closure."""
        session = self.session_factory()
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def check_connection(self) -> bool:
        """Verifies PostgreSQL connectivity by executing a lightweight ping query."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception as exc:
            sanitized = sanitize_error_message(exc, str(self._settings.database_url))
            raise DatabaseConnectionError(
                f"Failed to connect to PostgreSQL at {self._settings.redacted_database_url}: {sanitized}"
            ) from None

    def dispose(self) -> None:
        """Deterministically disposes the connection pool."""
        with self._lock:
            if self._engine is not None:
                self._engine.dispose()
                self._engine = None
            self._session_factory = None


_global_manager: DatabaseManager | None = None
_global_lock = threading.RLock()


def get_database_manager(settings: Settings | None = None) -> DatabaseManager:
    """Returns the process-wide DatabaseManager singleton."""
    global _global_manager
    if _global_manager is None or settings is not None:
        with _global_lock:
            if settings is not None:
                if _global_manager is not None:
                    _global_manager.dispose()
                _global_manager = DatabaseManager(settings)
            elif _global_manager is None:
                _global_manager = DatabaseManager()
    return _global_manager


def dispose_engine() -> None:
    """Disposes the process-wide database engine and cleans up connections."""
    global _global_manager
    with _global_lock:
        if _global_manager is not None:
            _global_manager.dispose()
            _global_manager = None


def reset_database_manager() -> None:
    """Disposes and resets the singleton for testing."""
    dispose_engine()


@contextmanager
def get_session(settings: Settings | None = None) -> Generator[Session, None, None]:
    """Convenience context manager yielding a managed session from the singleton manager."""
    manager = get_database_manager(settings)
    with manager.get_session() as session:
        yield session
