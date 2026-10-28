from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from zylar.persistence.database import get_database_manager
from zylar.persistence.dtos import IncidentCreate, PersistIncidentResult
from zylar.persistence.exceptions import PersistenceError
from zylar.persistence.repositories import (
    CheckpointRepository,
    IncidentRepository,
    OffenderHistoryRepository,
)


class UnitOfWork:
    """Transaction coordinator and session boundary owner for Zylar persistence operations.

    Controls transaction commit, rollback, and guaranteed session cleanup.
    Ensures that incident creation, constituent event references, risk records,
    entity-history increments, and audit logs are committed atomically.
    """

    def __init__(self, session_factory: sessionmaker[Session] | None = None) -> None:
        self._session_factory = session_factory
        self._session: Session | None = None
        self._committed: bool = False
        self.incidents: IncidentRepository | None = None
        self.offenders: OffenderHistoryRepository | None = None
        self.checkpoints: CheckpointRepository | None = None

    @property
    def session(self) -> Session:
        """Returns the active SQLAlchemy session owned by this UnitOfWork."""
        if self._session is None:
            raise PersistenceError("UnitOfWork is not active. Use 'with UnitOfWork():' context.")
        return self._session

    def __enter__(self) -> UnitOfWork:
        if self._session_factory is None:
            self._session_factory = get_database_manager().session_factory
        self._session = self._session_factory()
        self._committed = False
        self.incidents = IncidentRepository(self._session)
        self.offenders = OffenderHistoryRepository(self._session)
        self.checkpoints = CheckpointRepository(self._session)
        return self

    def commit(self) -> None:
        """Commits the active transaction."""
        if self._session is None:
            raise PersistenceError("Cannot commit: UnitOfWork is not active.")
        self._session.commit()
        self._committed = True

    def rollback(self) -> None:
        """Rolls back the active transaction."""
        if self._session is not None:
            self._session.rollback()

    def persist_incident_lifecycle(
        self,
        data: IncidentCreate,
        source_ips: list[str] | None = None,
        user_identifiers: list[str] | None = None,
    ) -> PersistIncidentResult:
        """Atomically persists an incident and updates offender histories in a single transaction.

        If the incident already exists with matching payload (idempotency replay):
          - Returns existing incident with created=False
          - Offender recurrence counts are NOT incremented
        If newly created:
          - Persists incident, event references, risk history, and audit log
          - Atomically increments offender recurrence counts for associated IPs and users
        """
        if self.incidents is None or self.offenders is None:
            raise PersistenceError("UnitOfWork must be active to persist an incident lifecycle.")

        result = self.incidents.create_incident(data)

        if result.created:
            ips = (
                source_ips
                if source_ips is not None
                else [ref.source_ip for ref in data.event_refs if ref.source_ip]
            )
            users = (
                user_identifiers
                if user_identifiers is not None
                else [ref.user_identifier for ref in data.event_refs if ref.user_identifier]
            )
            if ips or users:
                self.offenders.record_offenses(
                    ips=ips,
                    users=users,
                    risk_score=data.risk_score,
                    timestamp=data.timestamp,
                )

        return result

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if self._session is not None:
            try:
                if exc_type is not None:
                    self.rollback()
                elif not self._committed:
                    self.commit()
            finally:
                self._session.close()
                self._session = None
                self.incidents = None
                self.offenders = None
                self.checkpoints = None
