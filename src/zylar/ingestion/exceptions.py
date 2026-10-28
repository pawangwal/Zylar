"""Exceptions for Zylar Checkpointed Ingestion and Recovery."""

from __future__ import annotations


class IngestionError(Exception):
    """Base exception for all ingestion and checkpointing failures."""

    pass


class TransientIngestionError(IngestionError):
    """Temporary failure (e.g. network timeout, transient DB/ES disconnect) suitable for bounded retry."""

    pass


class PermanentIngestionError(IngestionError):
    """Unrecoverable failure (e.g. fatal configuration error, schema corruption)."""

    pass


class PoisonEventError(PermanentIngestionError):
    """Malformed or invalid event that cannot be parsed or normalized."""

    pass


class LeaseAcquisitionError(IngestionError):
    """Raised when an ingestion lease cannot be acquired or was stolen."""

    pass
