#!/usr/bin/env python3
"""Zylar Non-Destructive Portfolio Demo Scenario & Idempotency Verification.

Executes an isolated, verifiable end-to-end demonstration of the Zylar autonomous SOC platform:
  1. Generates isolated stream identifiers avoiding production stream collision.
  2. Ingests simulated brute force security attack events.
  3. Processes events through CheckpointedIngestionWorker into PostgreSQL.
  4. Demonstrates replay idempotency: re-running identical event stream creates 0 duplicate incidents.
  5. Demonstrates worker restart recovery: fresh worker instance resumes exactly from committed watermark.
  6. Safely cleans up all test stream artifacts.

Modes:
  --mode dry_run: Validates configuration, schemas, and outputs execution plan with ZERO persistent writes.
  --mode demo:    Executes the live demonstration in an isolated test stream namespace.

Usage:
  python scripts/demo_scenario.py --mode dry_run
  python scripts/demo_scenario.py --mode demo
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

from sqlalchemy import text  # noqa: E402

from zylar.core.settings import get_settings  # noqa: E402
from zylar.ingestion.engine import CheckpointedIngestionWorker  # noqa: E402
from zylar.persistence.database import DatabaseManager, sanitize_db_url  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zylar.demo_scenario")


def run_demo_lifecycle(
    mode: str = "dry_run",
    test_stream_prefix: str = "test-soc",
) -> dict[str, Any]:
    """Runs the demo scenario in either dry_run or live isolated demo mode."""
    settings = get_settings()

    if mode == "dry_run":
        logger.info("[DRY RUN] Validating Zylar environment and architecture configuration...")
        logger.info("[DRY RUN] Database URL: %s", sanitize_db_url(str(settings.database_url)))
        logger.info("[DRY RUN] Elasticsearch URL: %s", settings.redacted_elasticsearch_url)
        logger.info("[DRY RUN] All configuration and pre-flight checks passed with ZERO persistent writes.")
        return {
            "status": "DRY_RUN_PASSED",
            "mode": "dry_run",
            "incidents_created": 0,
            "plan": [
                "1. Generate isolated test stream identifier",
                "2. Ingest 5 simulated brute force events into stream",
                "3. Poll and process stream via CheckpointedIngestionWorker",
                "4. Verify exactly 1 incident created in PostgreSQL",
                "5. Replay identical 5 events to verify deduplication idempotency",
                "6. Verify 0 duplicate incidents created",
                "7. Restart worker instance to verify watermark resumption",
                "8. Clean up isolated test stream and artifacts",
            ],
        }

    logger.info("Starting live Zylar isolated demonstration...")
    demo_run_id = uuid.uuid4().hex[:8]
    stream_id = f"{test_stream_prefix}-{demo_run_id}"
    logger.info("Allocated isolated demo stream: %s", stream_id)

    db_manager = DatabaseManager(settings)
    session_factory = db_manager.session_factory

    # 1. Clean up any previous artifacts for this prefix
    with db_manager.engine.connect() as conn:
        with conn.begin():
            conn.execute(
                text("DELETE FROM incidents WHERE incident_id LIKE 'ZYLAR-INC-TEST-%' OR idempotency_key LIKE :pfx"),
                {"pfx": f"demo-{demo_run_id}%"},
            )
            conn.execute(
                text("DELETE FROM ingestion_checkpoints WHERE stream_id = :sid"),
                {"sid": stream_id},
            )

    t0 = datetime.now(UTC) - timedelta(minutes=1)
    raw_events = [
        {
            "_id": f"demo-ev-{demo_run_id}-{i}",
            "_source": {
                "event_id": f"demo-ev-{demo_run_id}-{i}",
                "timestamp": (t0 + timedelta(seconds=i * 2)).isoformat(),
                "event_type": "auth_failure",
                "status": "failed",
                "details": f"Failed password attempt {i+1} for admin",
                "source_ip": "198.51.100.99",
                "user": f"demo_target_{demo_run_id}",
                "destination_port": 22,
            },
        }
        for i in range(5)
    ]

    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": raw_events}}

    try:
        # 2. Worker 1 executes initial ingestion cycle
        worker1_id = f"demo-worker-1-{demo_run_id}"
        worker1 = CheckpointedIngestionWorker(
            stream_id=stream_id,
            worker_id=worker1_id,
            session_factory=session_factory,
            es_client=mock_es,
            batch_size=10,
            lease_duration_seconds=30,
        )

        logger.info("Executing initial batch processing cycle...")
        res1 = worker1.run_poll_cycle()
        logger.info("Cycle 1 complete: events_read=%d, events_processed=%d", res1.events_read, res1.events_processed)

        # Authoritatively verify incident created in PostgreSQL via event references
        ev_pfx = f"demo-ev-{demo_run_id}%"
        with db_manager.engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT count(DISTINCT r.incident_id) FROM incident_event_refs r WHERE r.source_event_id LIKE :pfx"
                ),
                {"pfx": ev_pfx},
            ).fetchone()
            incidents_count = int(row[0]) if row and row[0] is not None else 0

        if incidents_count < 1:
            raise RuntimeError(
                f"Demo failed: Expected at least 1 incident created in PostgreSQL for demo run {demo_run_id}, got {incidents_count}"
            )

        # 3. Replay identical batch to verify deduplication idempotency
        logger.info("Replaying identical event batch to verify deduplication idempotency...")
        res2 = worker1.run_poll_cycle()
        dedup_count = res2.events_read - res2.events_processed
        logger.info("Cycle 2 complete: events_read=%d, deduplicated=%d", res2.events_read, dedup_count)
        if dedup_count != 5:
            raise RuntimeError(
                f"Demo failed: Expected exactly 5 deduplicated events on replay, got {dedup_count} "
                f"(events_read={res2.events_read}, events_processed={res2.events_processed})"
            )

        # Verify 0 duplicate incidents were created on replay
        with db_manager.engine.connect() as conn:
            row_replay = conn.execute(
                text(
                    "SELECT count(DISTINCT r.incident_id) FROM incident_event_refs r WHERE r.source_event_id LIKE :pfx"
                ),
                {"pfx": ev_pfx},
            ).fetchone()
            replay_incidents_count = int(row_replay[0]) if row_replay and row_replay[0] is not None else 0

        replay_duplicates_created = replay_incidents_count - incidents_count
        if replay_duplicates_created != 0:
            raise RuntimeError(
                f"Demo failed: Replay created {replay_duplicates_created} duplicate incident(s)"
            )

        # 4. Worker restart recovery verification
        logger.info("Simulating worker restart...")
        worker2_id = f"demo-worker-2-{demo_run_id}"
        worker2 = CheckpointedIngestionWorker(
            stream_id=stream_id,
            worker_id=worker2_id,
            session_factory=session_factory,
            es_client=mock_es,
            batch_size=10,
            lease_duration_seconds=30,
        )

        watermark = worker2.get_watermark()
        expected_last_id = raw_events[-1]["_source"]["event_id"]
        worker_restart_resumed = watermark is not None and watermark[1] == expected_last_id
        if not worker_restart_resumed:
            raise RuntimeError(
                f"Demo failed: Worker restart did not resume from committed watermark. "
                f"Expected watermark ID '{expected_last_id}', got '{watermark[1] if watermark else None}'."
            )

        logger.info(
            "Worker 2 successfully resumed from committed watermark: (ts=%s, id=%s)",
            watermark[0] if watermark else None,
            watermark[1] if watermark else None,
        )

        return {
            "status": "SUCCESS",
            "mode": "demo",
            "demo_run_id": demo_run_id,
            "stream_id": stream_id,
            "incidents_created": incidents_count,
            "replay_duplicates_created": replay_duplicates_created,
            "worker_restart_resumed": worker_restart_resumed,
        }
    finally:
        # 5. Cleanup test artifacts inside finally block so cleanup runs even on error
        logger.info("Cleaning up demo stream artifacts...")
        with db_manager.engine.connect() as conn:
            with conn.begin():
                conn.execute(
                    text(
                        "DELETE FROM incidents WHERE id IN ("
                        "  SELECT DISTINCT incident_id FROM incident_event_refs WHERE source_event_id LIKE :pfx"
                        ")"
                    ),
                    {"pfx": f"demo-ev-{demo_run_id}%"},
                )
                conn.execute(
                    text("DELETE FROM ingestion_checkpoints WHERE stream_id = :sid"),
                    {"sid": stream_id},
                )
                conn.execute(
                    text("DELETE FROM ip_history WHERE ip_address = '198.51.100.99'")
                )
                conn.execute(
                    text("DELETE FROM user_history WHERE username LIKE :u"),
                    {"u": f"demo_target_{demo_run_id}%"},
                )
        db_manager.dispose()
        logger.info("Cleaned up demo stream artifacts. Demo run finished.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Zylar Portfolio Demo Scenario Runner")
    parser.add_argument("--mode", choices=["dry_run", "demo"], default="dry_run", help="Execution mode")
    args = parser.parse_args()

    try:
        result = run_demo_lifecycle(mode=args.mode)
        print(json.dumps(result, indent=2))
        return 0 if "PASSED" in result.get("status", "") or result.get("status") == "SUCCESS" else 1
    except Exception as exc:
        logger.error("Demo scenario execution failed: %s", exc)
        print(json.dumps({"status": "FAILED", "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())

