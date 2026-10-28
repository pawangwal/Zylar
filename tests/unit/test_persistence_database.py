from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from zylar.core.settings import Settings
from zylar.persistence.database import (
    DatabaseManager,
    dispose_engine,
    get_database_manager,
    get_session,
    reset_database_manager,
    sanitize_db_url,
    sanitize_error_message,
)
from zylar.persistence.exceptions import (
    DatabaseConfigurationError,
    DatabaseConnectionError,
)


def test_sanitize_db_url():
    url = "postgresql+psycopg://myuser:super_secret_pw@127.0.0.1:5434/mydb"
    sanitized = sanitize_db_url(url)
    assert "super_secret_pw" not in sanitized
    assert "myuser:***@127.0.0.1:5434/mydb" in sanitized


def test_sanitize_error_message():
    raw_url = "postgresql+psycopg://user:Pawangwal_Secret@host:5434/db"
    err = Exception("Connection to host:5434 failed with password Pawangwal_Secret")
    sanitized = sanitize_error_message(err, raw_url)
    assert "Pawangwal_Secret" not in sanitized
    assert "***" in sanitized


def test_unsupported_database_scheme_raises_configuration_error():
    settings = Settings(database_url="sqlite:///memory.db")
    mgr = DatabaseManager(settings)
    with pytest.raises(DatabaseConfigurationError, match="Unsupported database scheme"):
        _ = mgr.engine


def test_engine_creation_and_pool_settings():
    settings = Settings(
        database_url="postgresql+psycopg://zylar:mypassword123@127.0.0.1:5434/zylar_test",
        db_pool_size=7,
        db_max_overflow=15,
        db_pool_timeout_seconds=25,
        db_pool_recycle_seconds=900,
        db_pool_pre_ping=True,
    )
    mgr = DatabaseManager(settings)
    engine = mgr.engine
    assert engine.pool.size() == 7
    assert engine.pool._max_overflow == 15
    assert engine.pool._timeout == 25
    assert engine.pool._recycle == 900
    assert engine.pool._pre_ping is True
    mgr.dispose()


def test_session_lifecycle_success():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(return_value=mock_session)

    mgr = DatabaseManager()
    mgr._session_factory = mock_factory

    with mgr.get_session() as session:
        assert session is mock_session

    mock_session.close.assert_called_once()
    mock_session.rollback.assert_not_called()


def test_session_lifecycle_rollback_on_exception():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(return_value=mock_session)

    mgr = DatabaseManager()
    mgr._session_factory = mock_factory

    with pytest.raises(ValueError, match="simulated failure"):
        with mgr.get_session():
            raise ValueError("simulated failure")

    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def test_check_connection_failure_raises_sanitized_connection_error():
    settings = Settings(
        database_url="postgresql+psycopg://zylar:super_secret_pass@127.0.0.1:5434/nonexistent_db"
    )
    mgr = DatabaseManager(settings)

    with patch.object(
        mgr.engine,
        "connect",
        side_effect=OperationalError("SELECT 1", {}, Exception("super_secret_pass auth fail")),
    ):
        with pytest.raises(DatabaseConnectionError) as exc_info:
            mgr.check_connection()
        assert "super_secret_pass" not in str(exc_info.value)
        assert "***" in str(exc_info.value)
    mgr.dispose()


def test_global_manager_lifecycle():
    reset_database_manager()
    mgr1 = get_database_manager()
    mgr2 = get_database_manager()
    assert mgr1 is mgr2

    dispose_engine()
    mgr3 = get_database_manager()
    assert mgr3 is not mgr1
    dispose_engine()


def test_convenience_get_session():
    mock_session = MagicMock(spec=Session)
    mock_mgr = MagicMock(spec=DatabaseManager)
    mock_mgr.get_session.return_value.__enter__.return_value = mock_session

    with patch("zylar.persistence.database.get_database_manager", return_value=mock_mgr):
        with get_session() as session:
            assert session is mock_session
