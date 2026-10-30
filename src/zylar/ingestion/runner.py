"""Dedicated Ingestion Worker Runner for Zylar SOC Platform.

Implements standalone worker process execution (`python -m zylar.ingestion.runner`),
decoupled heartbeat persistence to PostgreSQL (`worker_instances`), optimistic lease
fencing, graceful signal draining on SIGINT/SIGTERM, and a process-local Prometheus
metrics HTTP server.
"""

from __future__ import annotations

import json
import logging
import signal
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import FrameType
from typing import Any

from elasticsearch import Elasticsearch
from sqlalchemy.orm import Session, sessionmaker

from zylar.core.logging import configure_logging
from zylar.core.metrics import get_metrics_collector
from zylar.core.settings import Settings, get_settings
from zylar.ingestion.engine import CheckpointedIngestionWorker, IngestionBatchResult
from zylar.persistence.database import DatabaseManager
from zylar.persistence.repositories import WorkerInstanceRepository

logger = logging.getLogger("ZYLAR-WorkerRunner")


class _MetricsHandler(BaseHTTPRequestHandler):
    """Internal HTTP handler serving Prometheus scrape format and health probes."""

    def do_GET(self) -> None:
        if self.path == "/metrics":
            collector = get_metrics_collector()
            payload = collector.get_prometheus_text().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path in ("/healthz", "/livez"):
            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard library HTTP server access logs
        pass


class IngestionRunner:
    """Standalone worker runner orchestrating ingestion batches, heartbeats, and lifecycle."""

    def __init__(
        self,
        worker_name: str | None = None,
        session_factory: sessionmaker[Session] | None = None,
        database_manager: DatabaseManager | None = None,
        es_client: Elasticsearch | None = None,
        ingestion_worker: CheckpointedIngestionWorker | None = None,
        settings: Settings | None = None,
        poll_interval_seconds: float = 10.0,
        heartbeat_interval_seconds: float = 10.0,
        metrics_port: int | None = None,
    ) -> None:
        self.worker_instance_id: str = str(uuid.uuid4())
        self._settings = settings or get_settings()
        self.worker_name: str = (worker_name or self._settings.worker_name).strip()
        self.hostname: str = socket.gethostname()
        self._poll_interval = poll_interval_seconds
        self._heartbeat_interval = heartbeat_interval_seconds
        self._metrics_port = metrics_port or self._settings.worker_metrics_port

        self._database_manager = database_manager
        self._session_factory = session_factory
        if self._session_factory is None:
            if self._database_manager is None:
                self._database_manager = DatabaseManager(
                    self._settings,
                    pool_size=self._settings.worker_db_pool_size,
                    max_overflow=self._settings.worker_db_max_overflow,
                )
            self._session_factory = self._database_manager.session_factory

        self._es_client = es_client
        self._ingestion_worker = ingestion_worker

        self._is_draining: bool = False
        self._stop_event = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._metrics_server: ThreadingHTTPServer | None = None
        self._metrics_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def is_draining(self) -> bool:
        return self._is_draining

    def should_continue_polling(self) -> bool:
        return not self._is_draining and not self._stop_event.is_set()

    def request_drain(self) -> None:
        """Signals worker to finish active work and refuse subsequent polling cycles."""
        logger.info(
            "Worker '%s' (%s) drain requested. Stopping new ingestion cycles.",
            self.worker_name,
            self.worker_instance_id,
        )
        self._is_draining = True

    def _heartbeat_tick(self) -> None:
        """Emits a single heartbeat to PostgreSQL worker_instances with independent session."""
        if self._session_factory is None:
            return
        status = "DRAINING" if self._is_draining else "HEALTHY"
        try:
            with self._session_factory() as session:
                with session.begin():
                    repo = WorkerInstanceRepository(session)
                    repo.register_or_heartbeat(
                        worker_instance_id=self.worker_instance_id,
                        worker_name=self.worker_name,
                        hostname=self.hostname,
                        status=status,
                    )
        except Exception as exc:
            logger.warning(
                "Heartbeat emission failed for worker '%s' (%s): %s",
                self.worker_name,
                self.worker_instance_id,
                exc,
            )

    def _heartbeat_loop(self) -> None:
        """Continuous background loop emitting periodic heartbeats."""
        while not self._stop_event.is_set():
            self._heartbeat_tick()
            self._stop_event.wait(self._heartbeat_interval)

    def start_heartbeat(self) -> None:
        """Starts the dedicated background heartbeat thread."""
        with self._lock:
            if self._heartbeat_thread is None:
                self._heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    name=f"worker-heartbeat-{self.worker_instance_id[:8]}",
                    daemon=True,
                )
                self._heartbeat_thread.start()
                logger.info(
                    "Heartbeat thread started for worker '%s' (%s) [interval=%ds].",
                    self.worker_name,
                    self.worker_instance_id,
                    self._heartbeat_interval,
                )

    def stop_heartbeat(self) -> None:
        """Stops the heartbeat loop."""
        with self._lock:
            if self._heartbeat_thread is not None:
                self._heartbeat_thread = None

    def start_metrics_server(self) -> None:
        """Starts the internal HTTP server providing Prometheus metrics."""
        with self._lock:
            if self._metrics_server is None:
                try:
                    self._metrics_server = ThreadingHTTPServer(
                        ("0.0.0.0", self._metrics_port),
                        _MetricsHandler,
                    )
                    self._metrics_thread = threading.Thread(
                        target=self._metrics_server.serve_forever,
                        name="worker-metrics-http",
                        daemon=True,
                    )
                    self._metrics_thread.start()
                    logger.info(
                        "Worker metrics HTTP server listening on http://0.0.0.0:%d/metrics",
                        self._metrics_port,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to start worker metrics server on port %d: %s",
                        self._metrics_port,
                        exc,
                    )

    def stop_metrics_server(self) -> None:
        """Shuts down the internal metrics HTTP server."""
        with self._lock:
            if self._metrics_server is not None:
                try:
                    self._metrics_server.shutdown()
                    self._metrics_server.server_close()
                except Exception as exc:
                    logger.warning("Error shutting down worker metrics server: %s", exc)
                self._metrics_server = None
                self._metrics_thread = None

    def _get_worker(self) -> CheckpointedIngestionWorker:
        if self._ingestion_worker is None:
            if self._es_client is None:
                self._es_client = Elasticsearch(**self._settings.elasticsearch_client_kwargs)
            self._ingestion_worker = CheckpointedIngestionWorker(
                stream_id="elasticsearch-soc-events",
                worker_id=f"{self.worker_name}:{self.worker_instance_id[:8]}",
                es_client=self._es_client,
                settings=self._settings,
                session_factory=self._session_factory,
            )
        return self._ingestion_worker

    def run_poll_cycle(self) -> IngestionBatchResult:
        """Executes a single batch poll cycle and records results in WorkerInstanceRepository."""
        if self._is_draining:
            return IngestionBatchResult(
                stream_id="elasticsearch-soc-events",
                status="DRAINING",
                events_read=0,
                events_processed=0,
            )

        worker = self._get_worker()
        result = worker.run_poll_cycle()

        if self._session_factory is not None:
            try:
                with self._session_factory() as session:
                    with session.begin():
                        repo = WorkerInstanceRepository(session)
                        if repo.get(self.worker_instance_id) is None:
                            repo.register_or_heartbeat(
                                worker_instance_id=self.worker_instance_id,
                                worker_name=self.worker_name,
                                hostname=self.hostname,
                                status="DRAINING" if self._is_draining else "ACTIVE",
                            )
                        if result.status == "SUCCESS":
                            repo.record_cycle_success(
                                worker_instance_id=self.worker_instance_id,
                                processed_count=result.events_processed,
                            )
                        elif result.status in (
                            "TRANSIENT_FAILURE",
                            "PERMANENT_FAILURE",
                            "LEASE_LOST",
                        ):
                            repo.record_cycle_failure(
                                worker_instance_id=self.worker_instance_id,
                                error_code=result.status,
                            )
            except Exception as exc:
                logger.warning(
                    "Failed to record cycle telemetry for worker '%s': %s",
                    self.worker_instance_id,
                    exc,
                )

        return result

    def shutdown(self) -> None:
        """Performs graceful shutdown, recording STOPPED status and releasing resources."""
        logger.info(
            "Initiating graceful shutdown for worker '%s' (%s)...",
            self.worker_name,
            self.worker_instance_id,
        )
        self.request_drain()
        self._stop_event.set()

        # Update database status to STOPPED
        if self._session_factory is not None:
            try:
                with self._session_factory() as session:
                    with session.begin():
                        repo = WorkerInstanceRepository(session)
                        if repo.get(self.worker_instance_id) is None:
                            repo.register_or_heartbeat(
                                worker_instance_id=self.worker_instance_id,
                                worker_name=self.worker_name,
                                hostname=self.hostname,
                                status="STOPPED",
                            )
                        else:
                            repo.record_shutdown(self.worker_instance_id)
                logger.info(
                    "Worker '%s' status transitioned to STOPPED.",
                    self.worker_instance_id,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to update worker shutdown status in database: %s",
                    exc,
                )

        self.stop_heartbeat()
        self.stop_metrics_server()

        if self._database_manager is not None:
            try:
                self._database_manager.dispose()
                logger.info("Worker database connection pool disposed.")
            except Exception as exc:
                logger.warning("Error disposing worker database manager: %s", exc)

        if self._es_client is not None:
            try:
                self._es_client.close()
                logger.info("Worker Elasticsearch client closed.")
            except Exception as exc:
                logger.warning("Error closing worker Elasticsearch client: %s", exc)

    def run(self) -> None:
        """Runs the continuous ingestion polling loop until drained or interrupted."""
        logger.info(
            "Starting Zylar Ingestion Runner '%s' (ID: %s)...",
            self.worker_name,
            self.worker_instance_id,
        )
        self.start_metrics_server()
        self.start_heartbeat()
        self._heartbeat_tick()

        try:
            while self.should_continue_polling():
                self.run_poll_cycle()
                if self.should_continue_polling():
                    self._stop_event.wait(self._poll_interval)
        finally:
            self.shutdown()


def main() -> None:
    """CLI entry point for `python -m zylar.ingestion.runner`."""
    settings = get_settings()
    configure_logging(settings)

    runner = IngestionRunner(settings=settings)

    def handle_signal(sig: int, frame: FrameType | None) -> None:
        sig_name = "SIGINT" if sig == signal.SIGINT else "SIGTERM"
        logger.info("Received signal %s. Commencing graceful drain.", sig_name)
        runner.request_drain()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    runner.run()


if __name__ == "__main__":
    main()
