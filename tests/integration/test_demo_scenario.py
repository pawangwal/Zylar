"""Integration tests for the non-destructive end-to-end demo scenario."""

from scripts.demo_scenario import run_demo_lifecycle


def test_dry_run_mode_performs_zero_persistent_writes():
    """dry_run=True must validate connectivity and plan steps, producing zero persistent incidents."""
    summary = run_demo_lifecycle(mode="dry_run")
    assert summary["status"] == "DRY_RUN_PASSED"
    assert summary["incidents_created"] == 0


def test_demo_mode_executes_in_isolated_environment():
    """mode='demo' generates unique run ID and tests replay idempotency and worker restart."""
    summary = run_demo_lifecycle(mode="demo", test_stream_prefix="test-soc")
    assert summary["status"] == "SUCCESS"
    assert summary["incidents_created"] == 1
    assert summary["replay_duplicates_created"] == 0
    assert summary["worker_restart_resumed"] is True

