"""Integration tests for automated database backup and disaster recovery verification drill."""

import pytest
from scripts.drills.backup_and_restore_drill import (
    assert_restore_target_safety,
    verify_database_parity,
)


def test_restore_target_safety_refuses_production_or_source_database():
    """Drill must refuse to restore if target database matches source database."""
    with pytest.raises(ValueError, match="Safety violation"):
        assert_restore_target_safety(source_db="zylar_db", target_db="zylar_db")

    with pytest.raises(ValueError, match="Safety violation"):
        assert_restore_target_safety(source_db="zylar_db", target_db="zylar_prod")

    with pytest.raises(ValueError, match="Safety violation"):
        assert_restore_target_safety(source_db="zylar_db", target_db="production_db")


def test_restore_target_safety_accepts_isolated_test_database():
    """Isolated test database names must be permitted."""
    assert_restore_target_safety(source_db="zylar_db", target_db="zylar_restore_test")
    assert_restore_target_safety(source_db="source_soc", target_db="drill_target_123")


def test_verify_database_parity_checks_sequence_state():
    """Verification must fail if sequence last_value is less than source sequence last_value."""
    source_seq = {"incidents_id_seq": {"last_value": 10, "is_called": True}}
    target_seq = {"incidents_id_seq": {"last_value": 5, "is_called": True}}
    with pytest.raises(ValueError, match="Sequence state mismatch"):
        verify_database_parity(
            source_counts={"incidents": 10},
            target_counts={"incidents": 10},
            source_sequences=source_seq,
            target_sequences=target_seq,
        )


def test_verify_database_parity_checks_row_counts():
    """Verification must fail if table row counts do not match."""
    source_counts = {"incidents": 10, "users": 3}
    target_counts = {"incidents": 9, "users": 3}
    with pytest.raises(ValueError, match="Row count mismatch"):
        verify_database_parity(
            source_counts=source_counts,
            target_counts=target_counts,
            source_sequences={},
            target_sequences={},
        )


def test_verify_database_parity_passes_on_exact_match():
    """Verification must succeed when row counts and sequence values match."""
    counts = {"incidents": 10, "users": 3, "worker_instances": 1}
    seqs = {"incidents_id_seq": {"last_value": 10, "is_called": True}}
    result = verify_database_parity(
        source_counts=counts,
        target_counts=counts,
        source_sequences=seqs,
        target_sequences=seqs,
    )
    assert result is True

