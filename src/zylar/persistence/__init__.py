"""PostgreSQL persistence layer for Zylar."""

from zylar.persistence.database import (
    DatabaseManager,
    dispose_engine,
    get_database_manager,
    get_session,
    reset_database_manager,
)
from zylar.persistence.dtos import (
    EventRefData,
    IncidentCreate,
    PersistIncidentResult,
)
from zylar.persistence.exceptions import (
    ConcurrencyError,
    ConstraintViolationError,
    DatabaseConfigurationError,
    DatabaseConnectionError,
    IdempotencyConflictError,
    PersistenceError,
    RecordNotFoundError,
)
from zylar.persistence.models import (
    AuditLogModel,
    Base,
    DeadLetterEventModel,
    IncidentEventRefModel,
    IncidentModel,
    IngestionCheckpointModel,
    IPHistoryModel,
    RiskHistoryModel,
    UserHistoryModel,
)
from zylar.persistence.repositories import (
    CheckpointRepository,
    IncidentRepository,
    OffenderHistoryRepository,
)
from zylar.persistence.unit_of_work import UnitOfWork

__all__ = [
    "AuditLogModel",
    "Base",
    "CheckpointRepository",
    "ConcurrencyError",
    "ConstraintViolationError",
    "DatabaseConfigurationError",
    "DatabaseConnectionError",
    "DatabaseManager",
    "DeadLetterEventModel",
    "EventRefData",
    "IdempotencyConflictError",
    "IPHistoryModel",
    "IncidentCreate",
    "IncidentEventRefModel",
    "IncidentModel",
    "IncidentRepository",
    "IngestionCheckpointModel",
    "OffenderHistoryRepository",
    "PersistIncidentResult",
    "PersistenceError",
    "RecordNotFoundError",
    "RiskHistoryModel",
    "UnitOfWork",
    "UserHistoryModel",
    "dispose_engine",
    "get_database_manager",
    "get_session",
    "reset_database_manager",
]
