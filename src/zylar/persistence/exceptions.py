from __future__ import annotations


class PersistenceError(Exception):
    """Base exception for all persistence layer errors."""

    pass


class DatabaseConfigurationError(PersistenceError):
    """Raised when database settings or connection URLs are malformed or invalid."""

    pass


class DatabaseConnectionError(PersistenceError):
    """Raised when connecting to PostgreSQL or checking out a connection fails."""

    pass


class RecordNotFoundError(PersistenceError):
    """Raised when an expected database record is not found."""

    pass


class IdempotencyConflictError(PersistenceError):
    """Raised when an idempotency key is reused with a conflicting request payload."""

    pass


class ConstraintViolationError(PersistenceError):
    """Raised when a database integrity constraint (check, foreign key) is violated."""

    pass


class ConcurrencyError(PersistenceError):
    """Raised when a concurrent transaction conflict or serialization failure occurs."""

    pass


class StaleLeaseError(PersistenceError):
    """Raised when a worker attempts to mutate or advance a checkpoint with a stale lease or generation mismatch."""

    pass
