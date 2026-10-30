from __future__ import annotations

import json
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import anyio
import ollama
from apscheduler.schedulers.background import BackgroundScheduler
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from elasticsearch.exceptions import ConnectionTimeout, TransportError
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from orchestrator.workflow_graph import build_workflow
from pydantic import BaseModel, Field

from zylar.analysis.correlation_service import CorrelationGraphResult, build_correlation_graph
from zylar.core.logging import configure_logging
from zylar.core.metrics import get_metrics_collector
from zylar.core.security import (
    Role,
    UserPrincipal,
    create_access_token,
    get_current_user,
    get_login_throttler,
    get_user_store,
    require_roles,
    sanitize_audit_details,
)
from zylar.core.settings import get_settings
from zylar.domain.workflow import WorkflowRequest
from zylar.ingestion.engine import CheckpointedIngestionWorker
from zylar.persistence.database import (
    DatabaseManager,
    get_database_manager,
    get_session,
)
from zylar.persistence.repositories import OffenderHistoryRepository
from zylar.persistence.unit_of_work import UnitOfWork

settings = get_settings()
configure_logging(settings)
logger = logging.getLogger("ZYLAR-Autonomous")

ES_HOST = str(settings.elasticsearch_url).rstrip("/")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


def check_for_threats() -> None:
    """Delegates autonomous ingestion check to CheckpointedIngestionWorker."""
    worker = getattr(app.state, "ingestion_worker", None)
    if worker is not None:
        worker.run_poll_cycle()
    else:
        logger.info("Autonomous ingestion skipped: scheduler/worker disabled in API process.")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manages application startup, shared database manager pool, and clean scheduler shutdown."""
    db_manager = get_database_manager(settings)
    app.state.db_manager = db_manager
    logger.info("Shared PostgreSQL DatabaseManager initialized on app.state.")

    scheduler: BackgroundScheduler | None = None
    if settings.enable_ingestion_scheduler:
        worker = CheckpointedIngestionWorker(
            stream_id="elasticsearch-soc-events",
            settings=settings,
            session_factory=db_manager.session_factory,
        )
        app.state.ingestion_worker = worker

        scheduler = BackgroundScheduler(timezone="UTC")
        scheduler.add_job(worker.run_poll_cycle, "interval", seconds=30, id="threat_scan")
        scheduler.start()
        app.state.scheduler = scheduler
        logger.info("Autonomous checkpointed ingestion scheduler started in lifespan context.")
    else:
        app.state.ingestion_worker = None
        app.state.scheduler = None
        logger.info("Ingestion scheduler disabled in this process (API-only mode).")

    yield

    if scheduler is not None:
        try:
            scheduler.shutdown(wait=False)
            logger.info("Autonomous background scheduler shut down cleanly.")
        except Exception as exc:
            logger.warning("Error during scheduler shutdown: %s", exc)

    try:
        db_manager.dispose()
        logger.info("Shared PostgreSQL DatabaseManager connection pool disposed.")
    except Exception as exc:
        logger.warning("Error during database manager disposal: %s", exc)


app = FastAPI(
    title="ZYLAR API - Autonomous Cybersecurity Platform",
    lifespan=lifespan,
)


_CORRELATION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next: Any) -> Any:
    """Attaches, validates, and propagates an X-Correlation-ID header across request/response life-cycle."""
    raw_corr_id = request.headers.get("X-Correlation-ID")
    if not raw_corr_id or not raw_corr_id.strip():
        corr_id = f"req-{uuid.uuid4().hex[:12]}"
    else:
        clean_id = raw_corr_id.strip()
        if not _CORRELATION_ID_PATTERN.match(clean_id):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "Invalid X-Correlation-ID header; must be 1-128 alphanumeric, hyphen, underscore, or dot characters.",
                    "correlation_id": f"req-{uuid.uuid4().hex[:12]}",
                },
                headers={"X-Correlation-ID": f"req-{uuid.uuid4().hex[:12]}"},
            )
        corr_id = clean_id

    request.state.correlation_id = corr_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = corr_id
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    corr_id = getattr(request.state, "correlation_id", f"req-{uuid.uuid4().hex[:12]}")
    headers = dict(exc.headers or {})
    headers["X-Correlation-ID"] = corr_id
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "correlation_id": corr_id},
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    corr_id = getattr(request.state, "correlation_id", f"req-{uuid.uuid4().hex[:12]}")
    sanitized_errors = []
    for err in exc.errors():
        err_dict = dict(err)
        # Scrub raw input to prevent secret or password reflection
        err_dict.pop("input", None)
        sanitized_errors.append(err_dict)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "details": jsonable_encoder(sanitized_errors),
            "correlation_id": corr_id,
        },
        headers={"X-Correlation-ID": corr_id},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    corr_id = getattr(request.state, "correlation_id", f"req-{uuid.uuid4().hex[:12]}")
    logger.error("Unhandled server exception [%s]: %s", corr_id, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error", "correlation_id": corr_id},
        headers={"X-Correlation-ID": corr_id},
    )


class TokenRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int


def get_client_ip(request: Request) -> str:
    """Extracts client IP, respecting X-Forwarded-For only when the immediate peer is in trusted_proxies."""
    remote_host = request.client.host if request.client else "127.0.0.1"
    trusted = set(settings.trusted_proxies)
    if remote_host in trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            hops = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
            for ip in reversed(hops):
                if ip not in trusted:
                    return ip
    return remote_host


@app.post("/api/auth/token", response_model=TokenResponse)
async def login_for_access_token(req: TokenRequest, request: Request) -> TokenResponse:
    """Authenticates against the trusted identity store and returns a signed access token."""
    client_ip = get_client_ip(request)
    throttler = get_login_throttler()

    # Check both IP and user throttles before authenticating
    throttler.check_rate_limit(f"ip:{client_ip}")
    throttler.check_rate_limit(f"user:{req.username}")

    user_store = get_user_store()
    principal = user_store.authenticate(req.username, req.password)
    if not principal:
        throttler.record_failure(f"ip:{client_ip}")
        throttler.record_failure(f"user:{req.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    throttler.record_success(f"ip:{client_ip}")
    throttler.record_success(f"user:{req.username}")

    token = create_access_token(principal.subject, principal.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=str(principal.role),
        expires_in=settings.token_expire_minutes * 60,
    )


@app.get("/health/live")
async def health_live() -> dict[str, Any]:
    """Liveness probe indicating the service process is up and responsive."""
    return {
        "status": "alive",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/health/ready")
async def health_ready(request: Request, response: Response) -> dict[str, Any]:
    """Readiness probe checking real operational readiness of dependencies.

    Checks Elasticsearch and PostgreSQL database. Treats Ollama as an optional
    dependency: if Ollama is unreachable, status is 'degraded' (HTTP 200) because
    the workflow operates safely with deterministic fallbacks. If critical dependencies
    fail, returns HTTP 503 Service Unavailable.

    Free of secrets and internal infrastructure connection details.
    """
    checks: dict[str, str] = {}
    is_ready = True
    is_degraded = False

    # 1. Check Elasticsearch
    try:
        es_kwargs = dict(settings.elasticsearch_client_kwargs)
        es_kwargs["request_timeout"] = 2.0
        es = Elasticsearch(**es_kwargs)
        es_ok = await anyio.to_thread.run_sync(es.ping)
        if es_ok:
            checks["elasticsearch"] = "healthy"
        else:
            checks["elasticsearch"] = "unhealthy"
            is_ready = False
    except Exception:
        checks["elasticsearch"] = "unhealthy"
        is_ready = False

    # 2. Check Database connectivity (PostgreSQL) strictly using lifespan-managed pool
    db_mgr: DatabaseManager | None = getattr(request.app.state, "db_manager", None)
    if db_mgr is None:
        logger.error("Readiness probe failed: app.state.db_manager is not initialized by lifespan.")
        checks["database"] = "unhealthy"
        is_ready = False
    else:
        try:
            db_ok = await anyio.to_thread.run_sync(db_mgr.check_connection)
            if db_ok:
                checks["database"] = "healthy"
            else:
                checks["database"] = "unhealthy"
                is_ready = False
        except Exception as exc:
            logger.warning("Database readiness probe error: %s", type(exc).__name__)
            checks["database"] = "unhealthy"
            is_ready = False

    # 3. Check Ollama (degraded optional dependency)
    try:

        def check_ollama() -> bool:
            client = ollama.Client(host=str(settings.ollama_url), timeout=2.0)
            client.list()
            return True

        ollama_ok = await anyio.to_thread.run_sync(check_ollama)
        checks["ollama"] = "healthy" if ollama_ok else "degraded"
    except Exception:
        checks["ollama"] = "degraded"
        is_degraded = True

    # 4. Report Autonomous Scheduler health check if configured
    sched = getattr(request.app.state, "scheduler", None)
    if sched is not None:
        sched_running = getattr(sched, "running", False)
        checks["scheduler"] = "healthy" if sched_running else "stopped"

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        overall_status = "unhealthy"
    elif is_degraded:
        overall_status = "degraded"
    else:
        overall_status = "ready"

    return {
        "status": overall_status,
        "checks": checks,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics() -> PlainTextResponse:
    """Exposes operational, ingestion, and SOC detection metrics in Prometheus exposition format."""
    text = get_metrics_collector().get_prometheus_text()
    return PlainTextResponse(text, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/ingestion/status")
async def get_ingestion_status(
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
) -> dict[str, Any]:
    """Returns ingestion checkpoint progress, watermark lag, dead-letter queue, and scheduler metrics."""
    db_mgr: DatabaseManager | None = getattr(request.app.state, "db_manager", None)
    session_factory = db_mgr.session_factory if db_mgr else None

    def query_status() -> dict[str, Any]:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            cp = uow.checkpoints.get("elasticsearch-soc-events")
            lag = uow.checkpoints.get_checkpoint_lag_seconds("elasticsearch-soc-events")
            dead_letters = uow.checkpoints.get_dead_letter_count("elasticsearch-soc-events")
            active_workers: list[dict[str, Any]] = []
            if uow.workers is not None:
                worker_models = uow.workers.get_active_workers(stale_threshold_seconds=60.0)
                now_utc = datetime.now(UTC)
                for w in worker_models:
                    hb_lag = (
                        (now_utc - w.last_heartbeat_at).total_seconds()
                        if w.last_heartbeat_at
                        else None
                    )
                    active_workers.append(
                        {
                            "worker_instance_id": w.worker_instance_id,
                            "worker_name": w.worker_name,
                            "hostname": w.hostname,
                            "status": w.status,
                            "last_heartbeat_at": (
                                w.last_heartbeat_at.isoformat() if w.last_heartbeat_at else None
                            ),
                            "heartbeat_lag_seconds": hb_lag,
                            "last_successful_cycle_at": (
                                w.last_successful_cycle_at.isoformat()
                                if w.last_successful_cycle_at
                                else None
                            ),
                            "last_failed_cycle_at": (
                                w.last_failed_cycle_at.isoformat()
                                if w.last_failed_cycle_at
                                else None
                            ),
                            "last_error_code": w.last_error_code,
                        }
                    )

        sched = getattr(request.app.state, "scheduler", None)
        sched_running = sched is not None and getattr(sched, "running", False)
        worker = getattr(request.app.state, "ingestion_worker", None)
        worker_status = worker.get_worker_status() if worker else {}
        scheduler_info = {
            "status": "active" if sched_running else ("offline" if sched is None else "stopped"),
            "running": sched_running,
            **worker_status,
        }

        if cp is None:
            return {
                "stream_id": "elasticsearch-soc-events",
                "status": "UNINITIALIZED",
                "last_processed_timestamp": None,
                "last_processed_id": None,
                "batch_sequence": 0,
                "events_processed_count": 0,
                "lag_seconds": None,
                "dead_letters_count": 0,
                "retry_count": 0,
                "last_error": None,
                "lease_owner": None,
                "lease_generation": None,
                "lease_expires_at": None,
                "scheduler": scheduler_info,
                "active_workers": active_workers,
                "workers_count": len(active_workers),
            }

        return {
            "stream_id": cp.stream_id,
            "status": cp.status,
            "last_processed_timestamp": cp.last_processed_timestamp.isoformat(),
            "last_processed_id": cp.last_processed_id,
            "batch_sequence": cp.batch_sequence,
            "events_processed_count": cp.events_processed_count,
            "lag_seconds": lag,
            "dead_letters_count": dead_letters,
            "retry_count": cp.retry_count,
            "last_error": sanitize_audit_details(cp.last_error) if cp.last_error else None,
            "lease_owner": cp.lease_owner,
            "lease_generation": cp.lease_generation,
            "lease_expires_at": (
                cp.lease_expires_at.isoformat() if cp.lease_expires_at else None
            ),
            "scheduler": scheduler_info,
            "active_workers": active_workers,
            "workers_count": len(active_workers),
        }

    return await anyio.to_thread.run_sync(query_status)


@app.get("/api/threat-graph")
async def get_threat_graph(
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
    minutes: Annotated[int, Query(ge=1, le=1440)] = 15,
    max_events: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> dict[str, Any]:
    """Generates the canonical bounded SOC threat correlation graph using the Task 3 correlation service."""
    try:
        es = Elasticsearch(**settings.elasticsearch_client_kwargs)
        now = datetime.now(UTC)
        past = now - timedelta(minutes=minutes)
        query = {
            "query": {"range": {"timestamp": {"gte": past.isoformat(), "lte": now.isoformat()}}},
            "size": max_events,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        res = await anyio.to_thread.run_sync(
            lambda: es.search(index=settings.elasticsearch_index, body=query)
        )
        logs = [
            hit["_source"]
            for hit in res.get("hits", {}).get("hits", [])
            if isinstance(hit.get("_source"), dict)
        ]
        logs = logs[:max_events]
        graph_result: CorrelationGraphResult = await anyio.to_thread.run_sync(
            lambda: build_correlation_graph(logs)
        )
        return {
            "dot_graph": graph_result.dot_representation,
            "total_nodes": graph_result.node_count,
            "total_edges": graph_result.edge_count,
            "top_entities": list(graph_result.top_entities),
            "centrality_score": graph_result.centrality_score,
            "input_event_count": graph_result.input_event_count,
            "processed_event_count": graph_result.processed_event_count,
            "event_limit_reached": graph_result.event_limit_reached,
            "node_limit_reached": graph_result.node_limit_reached,
            "edge_limit_reached": graph_result.edge_limit_reached,
            "truncated": graph_result.is_truncated,
        }
    except (ESConnectionError, ConnectionTimeout, TransportError, OSError) as exc:
        corr_id = getattr(request.state, "correlation_id", "unknown")
        logger.exception("Upstream search backend error building threat graph [%s]: %s", corr_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve log telemetry from search backend for threat correlation graph.",
        ) from exc
    except Exception as exc:
        corr_id = getattr(request.state, "correlation_id", "unknown")
        logger.exception("Failed to build threat graph [%s]: %s", corr_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error while computing threat correlation graph.",
        ) from exc


@app.post("/api/workflow/run")
async def run_workflow(
    req: WorkflowRequest,
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(require_roles(Role.ANALYST, Role.ADMIN))],
) -> dict[str, Any]:
    """Triggers the full agentic workflow on a bounded set of normalized events."""
    collector = get_metrics_collector()
    raw_logs = [ev.model_dump(mode="json") for ev in req.events]
    collector.record_events_received(len(raw_logs))
    t0 = datetime.now(UTC)

    try:
        graph = build_workflow()
        # Execute synchronous LangGraph workflow on bounded worker pool
        final_state = await anyio.to_thread.run_sync(graph.invoke, {"raw_logs": raw_logs})
        duration_sec = (datetime.now(UTC) - t0).total_seconds()
        collector.record_workflow_execution("success", duration_sec)
        collector.record_events_processed(len(raw_logs))
        collector.record_workflow_events_completed(len(raw_logs))
        if final_state.get("incident_id"):
            collector.record_incidents_persisted(1)

        rule_matches = final_state.get("rule_matches", [])
        if isinstance(rule_matches, list):
            for rm in rule_matches:
                if isinstance(rm, dict) and "rule_id" in rm:
                    collector.record_detection_rule_fired(str(rm["rule_id"]))
                elif hasattr(rm, "rule_id"):
                    collector.record_detection_rule_fired(str(rm.rule_id))

        return {
            "incident_id": final_state.get("incident_id"),
            "attack_classification": final_state.get("attack_classification"),
            "risk_score": final_state.get("risk_score"),
            "risk_category": final_state.get("risk_category"),
            "mitigation_plan": final_state.get("mitigation_plan"),
        }
    except Exception as exc:
        duration_sec = (datetime.now(UTC) - t0).total_seconds()
        collector.record_workflow_execution("failed", duration_sec)
        corr_id = getattr(request.state, "correlation_id", "unknown")
        logger.exception("Workflow execution error [%s]: %s", corr_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Workflow execution failed due to an internal processing error.",
        ) from exc


@app.get("/api/logs/recent")
async def get_recent_logs(
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
    minutes: Annotated[int, Query(ge=1, le=1440)] = 5,
) -> dict[str, Any]:
    """Fetches recent logs from Elasticsearch for authenticated users."""
    try:
        es = Elasticsearch(**settings.elasticsearch_client_kwargs)
        now = datetime.now(UTC)
        past = now - timedelta(minutes=minutes)
        query = {
            "query": {"range": {"timestamp": {"gte": past.isoformat(), "lte": now.isoformat()}}},
            "size": 1000,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        res = await anyio.to_thread.run_sync(
            lambda: es.search(index=settings.elasticsearch_index, body=query)
        )
        return {"logs": [hit["_source"] for hit in res["hits"]["hits"]]}
    except Exception as exc:
        corr_id = getattr(request.state, "correlation_id", "unknown")
        logger.exception("Failed to query recent logs [%s]: %s", corr_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve recent logs from search backend.",
        ) from exc


@app.get("/api/reports")
async def get_reports(
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
) -> dict[str, Any]:
    """Fetches generated incident reports for authenticated users."""

    def read_reports() -> list[dict[str, Any]]:
        loaded: list[dict[str, Any]] = []
        if os.path.exists(REPORTS_DIR):
            for file in os.listdir(REPORTS_DIR):
                if file.endswith(".json"):
                    with open(os.path.join(REPORTS_DIR, file), encoding="utf-8") as f:
                        try:
                            loaded.append(json.load(f))
                        except Exception:
                            pass
        loaded.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return loaded

    try:
        reports = await anyio.to_thread.run_sync(read_reports)
        return {"reports": reports}
    except Exception as exc:
        corr_id = getattr(request.state, "correlation_id", "unknown")
        logger.exception("Failed to read reports [%s]: %s", corr_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve incident reports.",
        ) from exc


def get_top_offenders(limit: int = 5) -> dict[str, list[dict[str, Any]]]:
    """Retrieves top offending IPs and users from PostgreSQL storage."""
    with get_session() as session:
        repo = OffenderHistoryRepository(session)
        return repo.get_top_offenders(limit)


@app.get("/api/offenders")
async def get_offenders(
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 5,
) -> dict[str, Any]:
    """Fetches top offenders from persistent storage for authenticated users."""
    try:
        data = await anyio.to_thread.run_sync(get_top_offenders, limit)
        return {"status": "success", "data": data}
    except Exception as exc:
        corr_id = getattr(request.state, "correlation_id", "unknown")
        logger.exception("Failed to fetch offenders [%s]: %s", corr_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve offender statistics from storage backend.",
        ) from exc
