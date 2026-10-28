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
from agents.anomaly_agent import detect_anomalies_node
from agents.log_analyzer import analyze_logs_node
from apscheduler.schedulers.background import BackgroundScheduler
from elasticsearch import Elasticsearch
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from orchestrator.workflow_graph import build_workflow
from pydantic import BaseModel, Field

from zylar.core.logging import configure_logging
from zylar.core.security import (
    Role,
    UserPrincipal,
    create_access_token,
    get_current_user,
    get_user_store,
    require_roles,
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
        fallback_worker = CheckpointedIngestionWorker(
            stream_id="elasticsearch-soc-events",
            settings=settings,
        )
        fallback_worker.run_poll_cycle()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manages application startup, shared database manager pool, and clean scheduler shutdown."""
    db_manager = get_database_manager(settings)
    app.state.db_manager = db_manager
    logger.info("Shared PostgreSQL DatabaseManager initialized on app.state.")

    worker = CheckpointedIngestionWorker(
        stream_id="elasticsearch-soc-events",
        settings=settings,
        session_factory=db_manager.session_factory,
    )
    app.state.ingestion_worker = worker

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(worker.run_poll_cycle, "interval", seconds=30, id="threat_scan")
    scheduler.start()
    logger.info("Autonomous checkpointed ingestion scheduler started in lifespan context.")

    yield

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
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "details": jsonable_encoder(exc.errors()),
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


@app.post("/api/auth/token", response_model=TokenResponse)
async def login_for_access_token(req: TokenRequest) -> TokenResponse:
    """Authenticates against the trusted identity store and returns a signed access token."""
    user_store = get_user_store()
    principal = user_store.authenticate(req.username, req.password)
    if not principal:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
        es = Elasticsearch([ES_HOST], request_timeout=2.0)
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


@app.get("/api/ingestion/status")
async def get_ingestion_status(
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
) -> dict[str, Any]:
    """Returns ingestion checkpoint progress, watermark lag, and dead-letter queue metrics."""
    db_mgr: DatabaseManager | None = getattr(request.app.state, "db_manager", None)
    session_factory = db_mgr.session_factory if db_mgr else None

    def query_status() -> dict[str, Any]:
        with UnitOfWork(session_factory) as uow:
            assert uow.checkpoints is not None
            cp = uow.checkpoints.get("elasticsearch-soc-events")
            lag = uow.checkpoints.get_checkpoint_lag_seconds("elasticsearch-soc-events")
            dead_letters = uow.checkpoints.get_dead_letter_count("elasticsearch-soc-events")

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
            "last_error": cp.last_error,
        }

    return await anyio.to_thread.run_sync(query_status)


@app.post("/api/workflow/run")
async def run_workflow(
    req: WorkflowRequest,
    request: Request,
    current_user: Annotated[UserPrincipal, Depends(require_roles(Role.ANALYST, Role.ADMIN))],
) -> dict[str, Any]:
    """Triggers the full agentic workflow on a bounded set of normalized events."""
    try:
        graph = build_workflow()
        raw_logs = [ev.model_dump(mode="json") for ev in req.events]
        # Execute synchronous LangGraph workflow on bounded worker pool
        final_state = await anyio.to_thread.run_sync(graph.invoke, {"raw_logs": raw_logs})

        return {
            "incident_id": final_state.get("incident_id"),
            "attack_classification": final_state.get("attack_classification"),
            "risk_score": final_state.get("risk_score"),
            "risk_category": final_state.get("risk_category"),
            "mitigation_plan": final_state.get("mitigation_plan"),
        }
    except Exception as exc:
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
        es = Elasticsearch([ES_HOST], request_timeout=settings.request_timeout_seconds)
        now = datetime.now(UTC)
        past = now - timedelta(minutes=minutes)
        query = {
            "query": {
                "range": {
                    "timestamp": {"gte": past.isoformat(), "lte": now.isoformat()}
                }
            },
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

