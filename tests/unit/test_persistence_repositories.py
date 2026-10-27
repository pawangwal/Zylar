from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zylar.persistence.dtos import EventRefData, IncidentCreate
from zylar.persistence.exceptions import (
    ConstraintViolationError,
    IdempotencyConflictError,
    RecordNotFoundError,
)
from zylar.persistence.models import IncidentModel
from zylar.persistence.repositories import (
    IncidentRepository,
    OffenderHistoryRepository,
)


def make_sample_incident_create(
    idempotency_key: str = "test-key-1",
    incident_id: str = "ZYLAR-INC-12345678",
    risk_score: int = 75,
    attack_classification: str = "Brute Force",
) -> IncidentCreate:
    return IncidentCreate(
        incident_id=incident_id,
        idempotency_key=idempotency_key,
        timestamp=datetime.now(UTC),
        attack_classification=attack_classification,
        risk_score=risk_score,
        risk_category="High",
        mitigation_plan=["Block IP"],
        threat_intel={"indicator": "bad_actor"},
        anomalous_events_count=2,
        status="NEW",
        event_refs=[
            EventRefData(
                event_source="suricata",
                source_event_id="evt-100",
                raw_event_hash="hash123",
                event_timestamp=datetime.now(UTC),
                source_ip="192.168.1.50",
                destination_port=22,
                user_identifier="admin",
            )
        ],
    )


def test_repository_does_not_commit_or_close_session():
    mock_session = MagicMock(spec=Session)
    repo = IncidentRepository(mock_session)

    # Calling any repository read or write method must never commit or close the caller's session
    repo.get_by_incident_id("ZYLAR-INC-TEST")
    mock_session.commit.assert_not_called()
    mock_session.close.assert_not_called()


def test_create_incident_idempotent_duplicate_returns_existing():
    mock_session = MagicMock(spec=Session)
    repo = IncidentRepository(mock_session)

    existing = IncidentModel(
        incident_id="ZYLAR-INC-EXISTING",
        idempotency_key="idemp-key-dup",
        timestamp=datetime.now(UTC),
        attack_classification="Brute Force",
        risk_score=75,
        risk_category="High",
        anomalous_events_count=2,
        status="NEW",
    )

    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = existing
    mock_session.execute.return_value = mock_execute

    payload = make_sample_incident_create(idempotency_key="idemp-key-dup")
    result = repo.create_incident(payload)

    assert result.created is False
    assert result.incident is existing
    assert result.idempotency_key == "idemp-key-dup"
    mock_session.commit.assert_not_called()


def test_create_incident_idempotency_payload_mismatch_raises_conflict():
    mock_session = MagicMock(spec=Session)
    repo = IncidentRepository(mock_session)

    existing = IncidentModel(
        incident_id="ZYLAR-INC-EXISTING",
        idempotency_key="idemp-key-mismatch",
        timestamp=datetime.now(UTC),
        attack_classification="SQL Injection",  # different classification!
        risk_score=90,
        risk_category="Critical",
        anomalous_events_count=10,
        status="NEW",
    )

    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = existing
    mock_session.execute.return_value = mock_execute

    payload = make_sample_incident_create(idempotency_key="idemp-key-mismatch")
    with pytest.raises(IdempotencyConflictError, match="conflicts with existing incident"):
        repo.create_incident(payload)


def test_create_incident_translates_unrelated_integrity_error_to_constraint_violation():
    mock_session = MagicMock(spec=Session)
    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_execute

    # Simulate check constraint violation in begin_nested
    mock_nested = MagicMock()
    mock_nested.__enter__.return_value = None
    mock_nested.__exit__.side_effect = IntegrityError(
        "INSERT", {}, Exception("chk_incidents_risk_score_range violated")
    )
    mock_session.begin_nested.return_value = mock_nested

    repo = IncidentRepository(mock_session)
    payload = make_sample_incident_create(risk_score=150)

    with pytest.raises(ConstraintViolationError, match="Integrity constraint violation"):
        repo.create_incident(payload)


def test_update_status_missing_record_raises_record_not_found():
    mock_session = MagicMock(spec=Session)
    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_execute

    repo = IncidentRepository(mock_session)
    with pytest.raises(RecordNotFoundError, match="not found"):
        repo.update_status(
            incident_id="ZYLAR-INC-NONEXISTENT",
            new_status="INVESTIGATING",
            actor="analyst1",
            correlation_id="corr-1",
        )


def test_update_status_invalid_status_raises_constraint_violation():
    mock_session = MagicMock(spec=Session)
    repo = IncidentRepository(mock_session)
    with pytest.raises(ConstraintViolationError, match="Invalid status"):
        repo.update_status(
            incident_id="ZYLAR-INC-1",
            new_status="INVALID_STATUS_VALUE",
            actor="analyst1",
            correlation_id="corr-1",
        )


def test_update_status_success_records_audit_and_flushes():
    mock_session = MagicMock(spec=Session)
    existing = IncidentModel(
        incident_id="ZYLAR-INC-1",
        idempotency_key="idemp-1",
        timestamp=datetime.now(UTC),
        attack_classification="Port Scan",
        risk_score=40,
        risk_category="Medium",
        status="NEW",
    )
    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = existing
    mock_session.execute.return_value = mock_execute

    repo = IncidentRepository(mock_session)
    updated = repo.update_status(
        incident_id="ZYLAR-INC-1",
        new_status="TRIAGED",
        actor="lead_analyst",
        correlation_id="corr-audit-99",
        reason="Initial triage completed",
    )

    assert updated.status == "TRIAGED"
    # An audit log model must be added and session flushed, but NOT committed
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()
    mock_session.commit.assert_not_called()


def test_offender_history_recurrence_calculation():
    mock_session = MagicMock(spec=Session)
    repo = OffenderHistoryRepository(mock_session)

    # 1. Zero offenses
    mock_exec_zero = MagicMock()
    mock_exec_zero.scalar.return_value = 0
    mock_session.execute.return_value = mock_exec_zero
    score_zero = repo.get_recurrence_factor(["10.0.0.1"], ["admin"])
    assert score_zero == 0

    # 2. 5 offenses -> 5 * 5 = 25
    mock_exec_some = MagicMock()
    mock_exec_some.scalar.return_value = 5
    mock_session.execute.return_value = mock_exec_some
    score_some = repo.get_recurrence_factor(["10.0.0.1"], [])
    assert score_some == 25

    # 3. 25 offenses -> 25 * 5 = 125 -> capped at 100
    mock_exec_high = MagicMock()
    mock_exec_high.scalar.return_value = 25
    mock_session.execute.return_value = mock_exec_high
    score_high = repo.get_recurrence_factor(["10.0.0.1"], [])
    assert score_high == 100
