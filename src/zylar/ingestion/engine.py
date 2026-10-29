"""Checkpointed Ingestion Worker for Zylar.

Implements persistent watermarks, worker leasing with monotonic generation fencing,
compound cursor pagination (timestamp, event_id.keyword), poison-event quarantine,
and atomic single-transaction persistence in PostgreSQL.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from agents.anomaly_agent import detect_anomalies_node
from agents.log_analyzer import analyze_logs_node
from agents.report_agent import parse_event_timestamp, save_report_artifacts
from agents.state import AgentState
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from elasticsearch.exceptions import ConnectionTimeout, TransportError
from orchestrator.workflow_graph import build_workflow
from sqlalchemy.orm import Session, sessionmaker

from zylar.core.settings import Settings, get_settings
from zylar.persistence.dtos import IncidentCreate
from zylar.persistence.exceptions import StaleLeaseError
from zylar.persistence.unit_of_work import UnitOfWork

logger = logging.getLogger("ZYLAR-IngestionEngine")


@dataclass(frozen=True)
class IngestionBatchResult:
    """Telemetry and outcome of a single ingestion batch execution."""

    stream_id: str
    status: (
        str  # SUCCESS, IDLE, LEASE_NOT_ACQUIRED, TRANSIENT_FAILURE, PERMANENT_FAILURE, QUARANTINED
    )
    events_read: int
    events_processed: int
    dead_letters_count: int = 0
    checkpoint_timestamp: datetime | None = None
    checkpoint_id: str | None = None
    error: str | None = None
    retry_count: int = 0


class CheckpointedIngestionWorker:
    """Resilient, checkpointed log ingestion engine.

    Guarantees that no checkpoint advances ahead of durable persistence,
    quarantines poison events without halting valid batches, enforces
    monotonic lease fencing tokens, and supports worker failover.
    """

    def __init__(
        self,
        stream_id: str = "elasticsearch-soc-events",
        worker_id: str | None = None,
        es_client: Elasticsearch | None = None,
        settings: Settings | None = None,
        session_factory: sessionmaker[Session] | None = None,
        workflow_invoker: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        batch_size: int = 100,
        lease_duration_seconds: int = 60,
        max_consecutive_failures: int = 5,
        backoff_initial_seconds: float = 2.0,
        backoff_max_seconds: float = 60.0,
        backoff_factor: float = 2.0,
    ) -> None:
        self.stream_id = stream_id
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self._settings = settings or get_settings()
        self._session_factory = session_factory
        self._es_client = es_client
        self._workflow_invoker = workflow_invoker
        if batch_size <= 0:
            raise ValueError("batch_size must be positive.")
        if lease_duration_seconds <= 0:
            raise ValueError("lease_duration_seconds must be positive.")

        self.batch_size = batch_size
        self.lease_duration_seconds = lease_duration_seconds
        self.max_consecutive_failures = max_consecutive_failures
        self.backoff_initial_seconds = backoff_initial_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self.backoff_factor = backoff_factor

    def _get_es_client(self) -> Elasticsearch:
        if self._es_client is None:
            self._es_client = Elasticsearch(
                [str(self._settings.elasticsearch_url).rstrip("/")],
                request_timeout=self._settings.request_timeout_seconds,
            )
        return self._es_client

    def _invoke_workflow(
        self,
        raw_logs: list[dict[str, Any]],
        defer_persistence: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "raw_logs": raw_logs,
            "defer_persistence": defer_persistence,
        }
        if self._workflow_invoker is not None:
            return self._workflow_invoker(payload)
        graph: Any = build_workflow()
        return cast(dict[str, Any], graph.invoke(payload))

    def poll_and_process_batch(self) -> IngestionBatchResult:
        """Executes a single checkpointed poll and process cycle."""
        # 1. Acquire lease with monotonic fencing token
        with UnitOfWork(self._session_factory) as uow:
            assert uow.checkpoints is not None
            acquired, lease_generation = uow.checkpoints.acquire_lease(
                stream_id=self.stream_id,
                worker_id=self.worker_id,
                lease_seconds=self.lease_duration_seconds,
                default_start_time=datetime.now(UTC) - timedelta(minutes=15),
            )
            uow.commit()

        if not acquired:
            logger.info(
                "Lease for stream '%s' is held by another active worker. Skipping cycle.",
                self.stream_id,
            )
            return IngestionBatchResult(
                stream_id=self.stream_id,
                status="LEASE_NOT_ACQUIRED",
                events_read=0,
                events_processed=0,
            )

        # 2. Read current committed checkpoint
        with UnitOfWork(self._session_factory) as uow:
            assert uow.checkpoints is not None
            cp = uow.checkpoints.get(self.stream_id)
            if cp is None:
                watermark_ts = datetime.now(UTC) - timedelta(minutes=15)
                watermark_id = None
            else:
                watermark_ts = cp.last_processed_timestamp
                watermark_id = cp.last_processed_id

        if watermark_ts.tzinfo is None:
            watermark_ts = watermark_ts.replace(tzinfo=UTC)

        # 3. Query Elasticsearch with stable ascending order and search_after cursor
        es = self._get_es_client()
        query: dict[str, Any] = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": watermark_ts.isoformat(),
                    }
                }
            },
            "sort": [
                {"timestamp": {"order": "asc"}},
                {"event_id.keyword": {"order": "asc", "unmapped_type": "keyword"}},
            ],
            "size": self.batch_size,
        }
        if watermark_id is not None:
            query["search_after"] = [watermark_ts.isoformat(), watermark_id]

        try:
            res = es.search(index=self._settings.elasticsearch_index, body=query)
            hits = res.get("hits", {}).get("hits", [])
        except (ESConnectionError, ConnectionTimeout, TransportError, OSError) as exc:
            logger.error("Transient error fetching events from Elasticsearch: %s", exc)
            return self._handle_failure(exc, lease_generation=lease_generation, is_transient=True)
        except Exception as exc:
            logger.error("Fatal or unclassified error connecting to Elasticsearch: %s", exc)
            return self._handle_failure(exc, lease_generation=lease_generation, is_transient=False)

        if not hits:
            # Nothing new to process; release lease to IDLE
            with UnitOfWork(self._session_factory) as uow:
                assert uow.checkpoints is not None
                uow.checkpoints.release_lease(self.stream_id, self.worker_id, lease_generation)
                uow.commit()
            return IngestionBatchResult(
                stream_id=self.stream_id,
                status="IDLE",
                events_read=0,
                events_processed=0,
                checkpoint_timestamp=watermark_ts,
                checkpoint_id=watermark_id,
            )

        # 4. Tie-breaker deduplication and poison event extraction
        eligible_hits: list[dict[str, Any]] = []
        for hit in hits:
            doc_id = str(hit.get("_id", ""))
            src = hit.get("_source") or {}
            event_id = str(src.get("event_id") or doc_id) if isinstance(src, dict) else doc_id
            hit_sort = hit.get("sort")
            es_sort_id = (
                str(hit_sort[1])
                if isinstance(hit_sort, list) and len(hit_sort) > 1 and hit_sort[1] is not None and str(hit_sort[1]).strip()
                else None
            )
            cursor_id = es_sort_id or event_id
            raw_ts = src.get("timestamp") if isinstance(src, dict) else None

            try:
                event_ts = parse_event_timestamp(raw_ts, event_id=event_id)
            except Exception:
                # Malformed timestamp; keep it for poison pill quarantine
                eligible_hits.append(hit)
                continue

            # Defensive tie-breaker skip for records already committed in previous batches
            if event_ts < watermark_ts:
                continue
            if event_ts == watermark_ts and watermark_id is not None and cursor_id <= watermark_id:
                continue

            eligible_hits.append(hit)

        if not eligible_hits:
            # All returned records were duplicates at the watermark boundary
            with UnitOfWork(self._session_factory) as uow:
                assert uow.checkpoints is not None
                uow.checkpoints.release_lease(self.stream_id, self.worker_id, lease_generation)
                uow.commit()
            return IngestionBatchResult(
                stream_id=self.stream_id,
                status="IDLE",
                events_read=len(hits),
                events_processed=0,
                checkpoint_timestamp=watermark_ts,
                checkpoint_id=watermark_id,
            )

        # 5. Quarantine poison events and extract valid records
        valid_records: list[dict[str, Any]] = []
        dead_letters: list[dict[str, Any]] = []
        latest_event_ts: datetime = watermark_ts
        latest_event_id: str | None = watermark_id

        for hit in eligible_hits:
            doc_id = str(hit.get("_id", ""))
            src = hit.get("_source")
            hit_sort = hit.get("sort")
            es_sort_id = (
                str(hit_sort[1])
                if isinstance(hit_sort, list) and len(hit_sort) > 1 and hit_sort[1] is not None and str(hit_sort[1]).strip()
                else None
            )

            if not isinstance(src, dict):
                dead_letters.append(
                    {
                        "event_id": doc_id,
                        "raw_payload": {"raw": str(src)},
                        "error_reason": "INVALID_EVENT_FORMAT",
                        "error_details": f"Expected dict for _source, got {type(src).__name__}",
                    }
                )
                cursor_id = es_sort_id or doc_id
                # Advance cursor tie-breaker past unparseable source
                if latest_event_id is None or cursor_id > latest_event_id:
                    latest_event_id = cursor_id
                continue

            event_id = str(src.get("event_id") or doc_id)
            cursor_id = es_sort_id or event_id
            try:
                parsed_ts = parse_event_timestamp(src.get("timestamp"), event_id=event_id)
            except Exception as exc:
                dead_letters.append(
                    {
                        "event_id": event_id,
                        "raw_payload": src,
                        "error_reason": "MALFORMED_TIMESTAMP",
                        "error_details": str(exc),
                    }
                )
                # Advance cursor past malformed event without fabricating timestamp
                if latest_event_id is None or cursor_id > latest_event_id:
                    latest_event_id = cursor_id
                continue

            # Ensure event carries deterministic ID
            record = dict(src)
            if "_id" not in record:
                record["_id"] = doc_id
            if "event_id" not in record:
                record["event_id"] = event_id

            valid_records.append(record)

            if parsed_ts > latest_event_ts or (
                parsed_ts == latest_event_ts
                and (latest_event_id is None or cursor_id > latest_event_id)
            ):
                latest_event_ts = parsed_ts
                latest_event_id = cursor_id

        # 6. If all hits were poisoned (no valid records), advance checkpoint and quarantine in one transaction
        if not valid_records:
            with UnitOfWork(self._session_factory) as uow:
                assert uow.checkpoints is not None
                if dead_letters:
                    uow.checkpoints.quarantine_events(self.stream_id, dead_letters)
                uow.checkpoints.advance_checkpoint(
                    stream_id=self.stream_id,
                    new_timestamp=latest_event_ts,
                    last_id=latest_event_id,
                    processed_count=0,
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                    lease_seconds=self.lease_duration_seconds,
                )
                uow.checkpoints.release_lease(self.stream_id, self.worker_id, lease_generation)
                uow.commit()

            return IngestionBatchResult(
                stream_id=self.stream_id,
                status="QUARANTINED",
                events_read=len(hits),
                events_processed=0,
                dead_letters_count=len(dead_letters),
                checkpoint_timestamp=latest_event_ts,
                checkpoint_id=latest_event_id,
            )

        # 7. Process valid events through anomaly detection and workflow (with defer_persistence=True)
        try:
            # Pre-screen for anomalies before invoking LLM workflow
            analyzed_state: AgentState = cast(
                AgentState, analyze_logs_node({"raw_logs": valid_records})
            )
            state = detect_anomalies_node(analyzed_state)

            workflow_result: dict[str, Any] = {}
            if state.get("anomalies") or self._workflow_invoker is not None:
                # Renew lease before long-running workflow/inference execution
                with UnitOfWork(self._session_factory) as uow:
                    assert uow.checkpoints is not None
                    renewed = uow.checkpoints.renew_lease(
                        stream_id=self.stream_id,
                        worker_id=self.worker_id,
                        lease_generation=lease_generation,
                        lease_seconds=self.lease_duration_seconds,
                    )
                    uow.commit()
                if not renewed:
                    logger.warning(
                        "Worker '%s' lost lease for stream '%s' (generation %d) prior to workflow execution.",
                        self.worker_id,
                        self.stream_id,
                        lease_generation,
                    )
                    return IngestionBatchResult(
                        stream_id=self.stream_id,
                        status="LEASE_LOST",
                        events_read=len(hits),
                        events_processed=0,
                        checkpoint_timestamp=watermark_ts,
                        checkpoint_id=watermark_id,
                    )

                logger.warning(
                    "Executing workflow for stream '%s' (anomalies=%d, custom_invoker=%s)...",
                    self.stream_id,
                    len(state.get("anomalies", [])),
                    self._workflow_invoker is not None,
                )
                workflow_result = self._invoke_workflow(valid_records, defer_persistence=True)
            else:
                logger.info(
                    "Processed %d events from stream '%s'; 0 statistical anomalies.",
                    len(valid_records),
                    self.stream_id,
                )

            incident_dto: IncidentCreate | None = workflow_result.get("incident_dto")
            contributing_ips = workflow_result.get("contributing_ips")
            contributing_users = workflow_result.get("contributing_users")

            # 8. Single atomic PostgreSQL transaction:
            # Persists incident lifecycle, dead-letter events, advances checkpoint, and releases lease.
            # If ANY operation fails, the entire transaction rolls back!
            with UnitOfWork(self._session_factory) as uow:
                assert uow.checkpoints is not None

                if incident_dto is not None:
                    uow.persist_incident_lifecycle(
                        incident_dto,
                        source_ips=contributing_ips,
                        user_identifiers=contributing_users,
                    )

                if dead_letters:
                    uow.checkpoints.quarantine_events(self.stream_id, dead_letters)

                uow.checkpoints.advance_checkpoint(
                    stream_id=self.stream_id,
                    new_timestamp=latest_event_ts,
                    last_id=latest_event_id,
                    processed_count=len(valid_records),
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                    lease_seconds=self.lease_duration_seconds,
                )
                uow.checkpoints.release_lease(self.stream_id, self.worker_id, lease_generation)
                uow.commit()

            # 9. Save file artifacts outside the transaction (failure does not compromise DB state)
            if incident_dto is not None:
                report_content = workflow_result.get("report_content", {})
                save_report_artifacts(report_content, incident_dto.mitigation_plan)

            return IngestionBatchResult(
                stream_id=self.stream_id,
                status="SUCCESS",
                events_read=len(hits),
                events_processed=len(valid_records),
                dead_letters_count=len(dead_letters),
                checkpoint_timestamp=latest_event_ts,
                checkpoint_id=latest_event_id,
            )

        except Exception as exc:
            logger.exception(
                "Error processing batch for stream '%s'; watermark will NOT advance: %s",
                self.stream_id,
                exc,
            )
            return self._handle_failure(exc, lease_generation=lease_generation, is_transient=True)

    def _handle_failure(
        self,
        exc: Exception,
        lease_generation: int,
        is_transient: bool,
    ) -> IngestionBatchResult:
        try:
            with UnitOfWork(self._session_factory) as uow:
                assert uow.checkpoints is not None
                cp = uow.checkpoints.record_failure(
                    stream_id=self.stream_id,
                    error=str(exc),
                    worker_id=self.worker_id,
                    lease_generation=lease_generation,
                    max_retries=self.max_consecutive_failures,
                    backoff_initial_seconds=self.backoff_initial_seconds,
                    backoff_factor=self.backoff_factor,
                    backoff_max_seconds=self.backoff_max_seconds,
                )
                uow.commit()
            status_code = "TRANSIENT_FAILURE" if cp.status == "RETRYING" else "PERMANENT_FAILURE"
            retry_count = cp.retry_count
            last_ts = cp.last_processed_timestamp
            last_id = cp.last_processed_id
        except StaleLeaseError:
            logger.warning(
                "Worker '%s' with generation %d is stale; cannot record failure for stream '%s'",
                self.worker_id,
                lease_generation,
                self.stream_id,
            )
            status_code = "PERMANENT_FAILURE"
            retry_count = 0
            last_ts = None
            last_id = None

        return IngestionBatchResult(
            stream_id=self.stream_id,
            status=status_code,
            events_read=0,
            events_processed=0,
            error=str(exc),
            retry_count=retry_count,
            checkpoint_timestamp=last_ts,
            checkpoint_id=last_id,
        )

    def run_poll_cycle(self) -> None:
        """Top-level invocation designed for BackgroundScheduler jobs."""
        try:
            res = self.poll_and_process_batch()
            if res.status not in ("IDLE", "LEASE_NOT_ACQUIRED"):
                logger.info(
                    "Ingestion cycle completed for '%s': status=%s, processed=%d, dead_letters=%d",
                    self.stream_id,
                    res.status,
                    res.events_processed,
                    res.dead_letters_count,
                )
        except Exception as exc:
            logger.error("Unhandled exception in ingestion worker cycle: %s", exc)
