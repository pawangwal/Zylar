from __future__ import annotations

import json
import logging
import os
import sqlite3
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
from memory.sqlite_manager import DB_PATH, get_top_offenders
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

settings = get_settings()
configure_logging(settings)
logger = logging.getLogger("ZYLAR-Autonomous")

ES_HOST = str(settings.elasticsearch_url).rstrip("/")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


def check_for_threats() -> None:
    """Background task to poll Elasticsearch and trigger workflows if anomalies detected."""
    logger.info("Autonomous System: Scanning for threats...")
    try:
        es = Elasticsearch([ES_HOST], request_timeout=settings.request_timeout_seconds)
        now = datetime.now(UTC)
        past = now - timedelta(seconds=30)
        query = {
            "query": {
                "range": {
                    "timestamp": {"gte": past.isoformat(), "lte": now.isoformat()}
                }
            },
            "size": 500,
        }
        res = es.search(index=settings.elasticsearch_index, body=query)
        logs = [hit["_source"] for hit in res["hits"]["hits"]]

        if not logs:
            logger.info("No logs in the last 30s.")
            return

        # Pre-check for anomalies locally before running the full LLM heavy graph
        state = analyze_logs_node({"raw_logs": logs})
        state = detect_anomalies_node(state)

        if state.get("anomalies"):
            logger.warning(
                "Detected %d anomalies! Triggering full workflow...", len(state["anomalies"])
            )
            graph = build_workflow()
            final_state = graph.invoke({"raw_logs": logs})
            logger.info("Incident %s recorded.", final_state.get("incident_id"))
        else:
            logger.info("Logs analyzed. No statistical anomalies found.")

    except Exception as e:
        logger.error("Error in autonomous check: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manages application startup and clean scheduler shutdown."""
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(check_for_threats, "interval", seconds=30, id="threat_scan")
    scheduler.start()
    logger.info("Autonomous background scheduler started in lifespan context.")

    yield

    try:
        scheduler.shutdown(wait=False)
        logger.info("Autonomous background scheduler shut down cleanly.")
    except Exception as exc:
        logger.warning("Error during scheduler shutdown: %s", exc)


app = FastAPI(
    title="ZYLAR API - Autonomous Cybersecurity Platform",
    lifespan=lifespan,
)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next: Any) -> Any:
    """Attaches or propagates an X-Correlation-ID header across request and response life-cycle."""
    corr_id = request.headers.get("X-Correlation-ID")
    if not corr_id or not corr_id.strip():
        corr_id = f"req-{uuid.uuid4().hex[:12]}"
    else:
        corr_id = corr_id.strip()

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
    logger.exception("Unhandled server exception [%s]: %s", corr_id, exc)
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
async def health_ready(response: Response) -> dict[str, Any]:
    """Readiness probe checking real operational readiness of dependencies.

    Checks Elasticsearch and SQLite memory database. Treats Ollama as an optional
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

    # 2. Check SQLite memory database
    try:
        def check_sqlite() -> bool:
            with sqlite3.connect(DB_PATH, timeout=2.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                row = cursor.fetchone()
                return row is not None

        sqlite_ok = await anyio.to_thread.run_sync(check_sqlite)
        if sqlite_ok:
            checks["sqlite"] = "healthy"
        else:
            checks["sqlite"] = "unhealthy"
            is_ready = False
    except Exception:
        checks["sqlite"] = "unhealthy"
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


@app.post("/api/workflow/run")
async def run_workflow(
    req: WorkflowRequest,
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/logs/recent")
async def get_recent_logs(
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
    except Exception as e:
        return {"error": str(e), "logs": []}


@app.get("/api/reports")
async def get_reports(
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
) -> dict[str, Any]:
    """Fetches generated incident reports for authenticated users."""
    def read_reports() -> list[dict[str, Any]]:
        loaded: list[dict[str, Any]] = []
        if os.path.exists(REPORTS_DIR):
            for file in os.listdir(REPORTS_DIR):
                if file.endswith(".json"):
                    with open(os.path.join(REPORTS_DIR, file)) as f:
                        try:
                            loaded.append(json.load(f))
                        except Exception:
                            pass
        loaded.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return loaded

    reports = await anyio.to_thread.run_sync(read_reports)
    return {"reports": reports}


@app.get("/api/offenders")
async def get_offenders(
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 5,
) -> dict[str, Any]:
    """Fetches top offenders from SQLite memory for authenticated users."""
    try:
        data = await anyio.to_thread.run_sync(get_top_offenders, limit)
        return {"status": "success", "data": data}
    except Exception as e:
        logger.error("Error fetching offenders: %s", e)
        return {"status": "error", "data": {"top_ips": [], "top_users": []}}
