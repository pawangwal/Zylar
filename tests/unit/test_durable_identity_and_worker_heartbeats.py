from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from zylar.persistence.exceptions import ConstraintViolationError, RecordNotFoundError
from zylar.persistence.models import Base
from zylar.persistence.repositories import (
    UserRepository,
    WorkerInstanceRepository,
)
from zylar.persistence.unit_of_work import UnitOfWork


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    # Create only users and worker_instances tables for unit testing in SQLite
    Base.metadata.create_all(
        engine, tables=[Base.metadata.tables["users"], Base.metadata.tables["worker_instances"]]
    )
    session_factory = sessionmaker(bind=engine)
    yield session_factory
    Base.metadata.drop_all(
        engine, tables=[Base.metadata.tables["worker_instances"], Base.metadata.tables["users"]]
    )
    engine.dispose()


def test_user_repository_create_and_query(in_memory_db):
    session = in_memory_db()
    repo = UserRepository(session)

    user = repo.create_user("analyst_alice", "hashed_pwd_123", role="analyst")
    session.commit()

    assert user.id is not None
    assert user.username == "analyst_alice"
    assert user.role == "analyst"
    assert user.disabled is False
    assert user.created_at is not None

    queried_by_id = repo.get_by_id(user.id)
    assert queried_by_id is not None
    assert queried_by_id.username == "analyst_alice"

    queried_by_name = repo.get_by_username("analyst_alice")
    assert queried_by_name is not None
    assert queried_by_name.id == user.id

    assert repo.get_by_username("non_existent") is None
    session.close()


def test_user_repository_validation_constraints(in_memory_db):
    session = in_memory_db()
    repo = UserRepository(session)

    # Blank username
    with pytest.raises(ConstraintViolationError):
        repo.create_user("", "hashed_pass")

    with pytest.raises(ConstraintViolationError):
        repo.create_user("   ", "hashed_pass")

    # Blank password hash
    with pytest.raises(ConstraintViolationError):
        repo.create_user("bob", "")

    # Invalid role
    with pytest.raises(ConstraintViolationError):
        repo.create_user("bob", "hashed_pass", role="superuser")

    session.close()


def test_user_repository_duplicate_username_rejected(in_memory_db):
    session = in_memory_db()
    repo = UserRepository(session)

    repo.create_user("duplicate_user", "hashed_pwd_1")
    session.commit()

    with pytest.raises(ConstraintViolationError):
        repo.create_user("duplicate_user", "hashed_pwd_2")

    session.close()


def test_user_repository_update_disabled_and_role(in_memory_db):
    session = in_memory_db()
    repo = UserRepository(session)

    user = repo.create_user("charlie", "pwd_hash", role="viewer")
    session.commit()

    # Update disabled
    updated = repo.update_disabled(user.id, True)
    session.commit()
    assert updated.disabled is True

    # Update role
    updated_role = repo.update_role(user.id, "analyst")
    session.commit()
    assert updated_role.role == "analyst"

    # Reject invalid role
    with pytest.raises(ConstraintViolationError):
        repo.update_role(user.id, "root")

    # Non-existent user
    non_existent = uuid.uuid4()
    with pytest.raises(RecordNotFoundError):
        repo.update_disabled(non_existent, False)
    with pytest.raises(RecordNotFoundError):
        repo.update_role(non_existent, "admin")

    session.close()


def test_user_repository_list_users(in_memory_db):
    session = in_memory_db()
    repo = UserRepository(session)

    repo.create_user("user_active_1", "pwd_1")
    u2 = repo.create_user("user_active_2", "pwd_2")
    u3 = repo.create_user("user_disabled", "pwd_3")
    repo.update_disabled(u3.id, True)
    session.commit()

    active_users = repo.list_users(include_disabled=False)
    assert len(active_users) == 2
    assert {u.username for u in active_users} == {"user_active_1", "user_active_2"}

    all_users = repo.list_users(include_disabled=True)
    assert len(all_users) == 3

    paged = repo.list_users(include_disabled=True, limit=1, offset=1)
    assert len(paged) == 1
    assert paged[0].username == u2.username

    session.close()


def test_worker_instance_repository_lifecycle(in_memory_db):
    session = in_memory_db()
    repo = WorkerInstanceRepository(session)

    # 1. Register new worker
    worker = repo.register_or_heartbeat(
        "worker-1", "ingestion-worker", "host-soc-01", status="STARTING"
    )
    session.commit()

    assert worker.worker_instance_id == "worker-1"
    assert worker.worker_name == "ingestion-worker"
    assert worker.hostname == "host-soc-01"
    assert worker.status == "STARTING"
    assert worker.last_successful_cycle_at is None

    # 2. Heartbeat on existing worker
    initial_hb = worker.last_heartbeat_at
    worker2 = repo.register_or_heartbeat(
        "worker-1", "ingestion-worker", "host-soc-01", status="ACTIVE"
    )
    session.commit()
    assert worker2.status == "ACTIVE"
    assert worker2.last_heartbeat_at >= initial_hb

    # 3. Successful cycle
    repo.record_cycle_success("worker-1")
    session.commit()
    refreshed = repo.get("worker-1")
    assert refreshed is not None
    assert refreshed.status == "ACTIVE"
    assert refreshed.last_successful_cycle_at is not None
    assert refreshed.last_error_code is None

    # 4. Failure cycle
    repo.record_cycle_failure("worker-1", "ELASTICSEARCH_UNAVAILABLE")
    session.commit()
    refreshed_failed = repo.get("worker-1")
    assert refreshed_failed is not None
    assert refreshed_failed.status == "DEGRADED"
    assert refreshed_failed.last_failed_cycle_at is not None
    assert refreshed_failed.last_error_code == "ELASTICSEARCH_UNAVAILABLE"

    # 5. Shutdown
    repo.record_shutdown("worker-1")
    session.commit()
    refreshed_stopped = repo.get("worker-1")
    assert refreshed_stopped is not None
    assert refreshed_stopped.status == "STOPPED"

    session.close()


def test_worker_instance_validation_and_errors(in_memory_db):
    session = in_memory_db()
    repo = WorkerInstanceRepository(session)

    with pytest.raises(ConstraintViolationError):
        repo.register_or_heartbeat("", "name", "host")

    with pytest.raises(ConstraintViolationError):
        repo.register_or_heartbeat("w1", "", "host")

    with pytest.raises(ConstraintViolationError):
        repo.register_or_heartbeat("w1", "name", "")

    with pytest.raises(ConstraintViolationError):
        repo.register_or_heartbeat("w1", "name", "host", status="INVALID_STATUS")

    with pytest.raises(RecordNotFoundError):
        repo.record_cycle_success("non-existent-worker")

    with pytest.raises(RecordNotFoundError):
        repo.record_cycle_failure("non-existent-worker", "ERR_CODE")

    session.close()


def test_worker_instance_active_and_pruning(in_memory_db):
    session = in_memory_db()
    repo = WorkerInstanceRepository(session)

    # Active worker
    repo.register_or_heartbeat("worker-live", "ingestion-worker", "host-1", status="ACTIVE")

    # Stopped worker
    repo.register_or_heartbeat("worker-stopped", "ingestion-worker", "host-2", status="ACTIVE")
    repo.record_shutdown("worker-stopped")

    session.commit()

    active = repo.get_active_workers(stale_threshold_seconds=60.0)
    assert len(active) == 1
    assert active[0].worker_instance_id == "worker-live"

    # Worker with stale heartbeat in the past
    stale_worker = repo.get("worker-stopped")
    assert stale_worker is not None
    stale_worker.last_heartbeat_at = datetime.now(UTC) - timedelta(days=2)
    session.commit()

    pruned = repo.prune_stale_workers(older_than_seconds=86400.0)
    assert pruned == 1
    assert repo.get("worker-stopped") is None
    assert repo.get("worker-live") is not None

    session.close()


def test_unit_of_work_manages_users_and_workers(in_memory_db):
    uow = UnitOfWork(in_memory_db)
    with uow:
        assert uow.users is not None
        assert uow.workers is not None
        user = uow.users.create_user("uow_user", "hashed_pwd", role="admin")
        uow.workers.register_or_heartbeat("uow-worker", "ingestion", "host-1")
        user_id = user.id
        uow.commit()

    with uow:
        assert uow.users.get_by_id(user_id) is not None
        assert uow.workers.get("uow-worker") is not None
