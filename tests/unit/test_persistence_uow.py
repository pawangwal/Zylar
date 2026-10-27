from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session, sessionmaker

from zylar.persistence.dtos import IncidentCreate, PersistIncidentResult
from zylar.persistence.exceptions import PersistenceError
from zylar.persistence.models import IncidentModel
from zylar.persistence.unit_of_work import UnitOfWork


def test_uow_access_outside_context_raises_persistence_error():
    uow = UnitOfWork()
    with pytest.raises(PersistenceError, match="not active"):
        _ = uow.session


def test_uow_lifecycle_commit_on_clean_exit():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(spec=sessionmaker, return_value=mock_session)

    uow = UnitOfWork(session_factory=mock_factory)
    with uow:
        assert uow.session is mock_session
        assert uow.incidents is not None
        assert uow.offenders is not None

    mock_session.commit.assert_called_once()
    mock_session.rollback.assert_not_called()
    mock_session.close.assert_called_once()
    assert uow.incidents is None
    assert uow.offenders is None


def test_uow_lifecycle_rollback_on_exception():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(spec=sessionmaker, return_value=mock_session)

    uow = UnitOfWork(session_factory=mock_factory)
    with pytest.raises(RuntimeError, match="operation failed"):
        with uow:
            raise RuntimeError("operation failed")

    mock_session.rollback.assert_called_once()
    mock_session.commit.assert_not_called()
    mock_session.close.assert_called_once()


def test_uow_explicit_commit():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(spec=sessionmaker, return_value=mock_session)

    uow = UnitOfWork(session_factory=mock_factory)
    with uow:
        uow.commit()

    # Commit called once by explicit commit; exit block should not duplicate commit
    mock_session.commit.assert_called_once()
    mock_session.close.assert_called_once()


def test_persist_incident_lifecycle_increments_offenders_on_creation():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(spec=sessionmaker, return_value=mock_session)

    uow = UnitOfWork(session_factory=mock_factory)
    with uow:
        # Mock repository methods
        mock_inc = MagicMock()
        mock_off = MagicMock()
        uow.incidents = mock_inc
        uow.offenders = mock_off

        dummy_incident = MagicMock(spec=IncidentModel)
        mock_inc.create_incident.return_value = PersistIncidentResult(
            incident=dummy_incident,
            created=True,
            idempotency_key="key-new",
        )

        mock_data = MagicMock(spec=IncidentCreate)
        mock_data.risk_score = 80
        mock_data.timestamp = MagicMock()
        mock_data.event_refs = []

        result = uow.persist_incident_lifecycle(
            mock_data,
            source_ips=["192.168.1.100"],
            user_identifiers=["analyst_evil"],
        )

        assert result.created is True
        mock_inc.create_incident.assert_called_once_with(mock_data)
        mock_off.record_offenses.assert_called_once_with(
            ips=["192.168.1.100"],
            users=["analyst_evil"],
            risk_score=80,
            timestamp=mock_data.timestamp,
        )


def test_persist_incident_lifecycle_does_not_increment_offenders_on_duplicate():
    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(spec=sessionmaker, return_value=mock_session)

    uow = UnitOfWork(session_factory=mock_factory)
    with uow:
        mock_inc = MagicMock()
        mock_off = MagicMock()
        uow.incidents = mock_inc
        uow.offenders = mock_off

        dummy_incident = MagicMock(spec=IncidentModel)
        mock_inc.create_incident.return_value = PersistIncidentResult(
            incident=dummy_incident,
            created=False,  # Replay duplicate!
            idempotency_key="key-existing",
        )

        mock_data = MagicMock(spec=IncidentCreate)
        mock_data.event_refs = []

        result = uow.persist_incident_lifecycle(
            mock_data,
            source_ips=["192.168.1.100"],
            user_identifiers=["analyst_evil"],
        )

        assert result.created is False
        mock_inc.create_incident.assert_called_once_with(mock_data)
        # MUST NOT increment offender history on duplicate replay!
        mock_off.record_offenses.assert_not_called()
