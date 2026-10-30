from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID

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


def test_model_classes_mapped():
    """Verifies that all model classes define expected table names and map to Base."""
    assert IncidentModel.__tablename__ == "incidents"
    assert IncidentEventRefModel.__tablename__ == "incident_event_refs"
    assert IPHistoryModel.__tablename__ == "ip_history"
    assert UserHistoryModel.__tablename__ == "user_history"
    assert RiskHistoryModel.__tablename__ == "risk_history"
    assert AuditLogModel.__tablename__ == "audit_logs"
    assert IngestionCheckpointModel.__tablename__ == "ingestion_checkpoints"
    assert DeadLetterEventModel.__tablename__ == "dead_letter_events"


def test_metadata_contains_all_ten_tables():
    """Verifies that Base.metadata registers exactly the ten required PostgreSQL tables."""
    table_names = set(Base.metadata.tables.keys())
    expected = {
        "incidents",
        "incident_event_refs",
        "ip_history",
        "user_history",
        "risk_history",
        "audit_logs",
        "ingestion_checkpoints",
        "dead_letter_events",
        "users",
        "worker_instances",
    }
    assert table_names == expected


def test_users_table_columns_and_constraints():
    table = Base.metadata.tables["users"]
    assert "id" in table.columns
    assert "username" in table.columns
    assert "hashed_password" in table.columns
    assert "role" in table.columns
    assert "disabled" in table.columns
    assert table.columns["username"].unique is True

    chk_names = {c.name for c in table.constraints if hasattr(c, "name") and c.name}
    assert "chk_users_role" in chk_names
    assert "chk_users_username_not_blank" in chk_names
    assert "chk_users_hashed_password_not_blank" in chk_names


def test_worker_instances_table_columns_and_constraints():
    table = Base.metadata.tables["worker_instances"]
    assert "worker_instance_id" in table.columns
    assert "worker_name" in table.columns
    assert "hostname" in table.columns
    assert "started_at" in table.columns
    assert "last_heartbeat_at" in table.columns
    assert "status" in table.columns

    chk_names = {c.name for c in table.constraints if hasattr(c, "name") and c.name}
    assert "chk_worker_status" in chk_names
    assert "chk_worker_instance_id_not_blank" in chk_names
    assert "chk_worker_name_not_blank" in chk_names


def test_incidents_table_columns_and_types():
    table = Base.metadata.tables["incidents"]

    # UUID primary key with server_default gen_random_uuid
    id_col = table.columns["id"]
    assert isinstance(id_col.type, UUID)
    assert id_col.primary_key is True
    assert id_col.server_default is not None

    # Unique constraints
    assert table.columns["incident_id"].unique is True
    assert table.columns["idempotency_key"].unique is True

    # Timezone-aware timestamp columns
    assert isinstance(table.columns["timestamp"].type, DateTime)
    assert table.columns["timestamp"].type.timezone is True
    assert isinstance(table.columns["created_at"].type, DateTime)
    assert table.columns["created_at"].type.timezone is True
    assert isinstance(table.columns["updated_at"].type, DateTime)
    assert table.columns["updated_at"].type.timezone is True

    # JSONB columns
    assert isinstance(table.columns["mitigation_plan"].type, JSONB)
    assert isinstance(table.columns["threat_intel"].type, JSONB)

    # Check constraints
    chk_names = {c.name for c in table.constraints if hasattr(c, "name") and c.name}
    assert "chk_incidents_risk_score_range" in chk_names
    assert "chk_incidents_anomalous_events_nonneg" in chk_names
    assert "chk_incidents_valid_status" in chk_names
    assert "chk_incidents_id_not_blank" in chk_names
    assert "chk_incidents_classification_not_blank" in chk_names
    assert "chk_incidents_category_not_blank" in chk_names


def test_incident_event_refs_foreign_key_and_uniqueness():
    table = Base.metadata.tables["incident_event_refs"]

    # Foreign key to incidents.id with CASCADE
    fks = list(table.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.column.table.name == "incidents"
    assert fk.ondelete == "CASCADE"

    # Unique constraint across (incident_id, event_source, source_event_id)
    uq_names = {c.name for c in table.constraints if hasattr(c, "name") and c.name}
    assert "uq_incident_source_event" in uq_names


def test_entity_history_check_constraints():
    ip_table = Base.metadata.tables["ip_history"]
    user_table = Base.metadata.tables["user_history"]

    ip_chks = {c.name for c in ip_table.constraints if hasattr(c, "name") and c.name}
    assert "chk_ip_history_offense_nonneg" in ip_chks
    assert "chk_ip_history_last_risk_range" in ip_chks
    assert "chk_ip_history_address_not_blank" in ip_chks

    user_chks = {c.name for c in user_table.constraints if hasattr(c, "name") and c.name}
    assert "chk_user_history_offense_nonneg" in user_chks
    assert "chk_user_history_last_risk_range" in user_chks
    assert "chk_user_history_username_not_blank" in user_chks


def test_risk_history_and_audit_logs_constraints():
    risk_table = Base.metadata.tables["risk_history"]
    audit_table = Base.metadata.tables["audit_logs"]

    risk_chks = {c.name for c in risk_table.constraints if hasattr(c, "name") and c.name}
    assert "chk_risk_history_score_range" in risk_chks

    audit_chks = {c.name for c in audit_table.constraints if hasattr(c, "name") and c.name}
    assert "chk_audit_logs_actor_not_blank" in audit_chks
    assert "chk_audit_logs_action_not_blank" in audit_chks
    assert "chk_audit_logs_correlation_not_blank" in audit_chks

    # Audit log incident_id is nullable with SET NULL
    audit_fks = list(audit_table.foreign_keys)
    assert len(audit_fks) == 1
    assert audit_fks[0].ondelete == "SET NULL"


def test_incident_model_python_defaults():
    """Verifies client-side model instantiation generates valid defaults."""
    now = datetime.now(UTC)
    incident = IncidentModel(
        incident_id="ZYLAR-INC-20261027-TEST",
        idempotency_key="req:test-12345",
        timestamp=now,
        attack_classification="Brute Force",
        risk_score=75,
        risk_category="High",
    )
    assert isinstance(incident.id, uuid.UUID)
    assert incident.status == "NEW"
    assert incident.anomalous_events_count == 0
