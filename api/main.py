from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from agents.anomaly_agent import detect_anomalies_node
from agents.log_analyzer import analyze_logs_node
from apscheduler.schedulers.background import BackgroundScheduler
from elasticsearch import Elasticsearch
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from memory.sqlite_manager import get_top_offenders
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

app = FastAPI(title="ZYLAR API - Autonomous Cybersecurity Platform")
ES_HOST = str(settings.elasticsearch_url).rstrip("/")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


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


@app.post("/api/workflow/run")
async def run_workflow(
    req: WorkflowRequest,
    current_user: Annotated[UserPrincipal, Depends(require_roles(Role.ANALYST, Role.ADMIN))],
) -> dict[str, Any]:
    """Triggers the full agentic workflow on a bounded set of normalized events."""
    try:
        graph = build_workflow()
        raw_logs = [ev.model_dump(mode="json") for ev in req.events]
        final_state = graph.invoke({"raw_logs": raw_logs})

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
        res = es.search(index="zylar-logs", body=query)
        return {"logs": [hit["_source"] for hit in res["hits"]["hits"]]}
    except Exception as e:
        return {"error": str(e), "logs": []}


@app.get("/api/reports")
async def get_reports(
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
) -> dict[str, Any]:
    """Fetches generated incident reports for authenticated users."""
    reports = []
    if os.path.exists(REPORTS_DIR):
        for file in os.listdir(REPORTS_DIR):
            if file.endswith(".json"):
                with open(os.path.join(REPORTS_DIR, file)) as f:
                    try:
                        reports.append(json.load(f))
                    except Exception:
                        pass

    # Sort by timestamp descending
    reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"reports": reports}


@app.get("/api/offenders")
async def get_offenders(
    current_user: Annotated[UserPrincipal, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 5,
) -> dict[str, Any]:
    """Fetches top offenders from SQLite memory for authenticated users."""
    try:
        data = get_top_offenders(limit=limit)
        return {"status": "success", "data": data}
    except Exception as e:
        logger.error("Error fetching offenders: %s", e)
        return {"status": "error", "data": {"top_ips": [], "top_users": []}}


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
        res = es.search(index="zylar-logs", body=query)
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


@app.on_event("startup")
def start_scheduler() -> None:
    scheduler = BackgroundScheduler()
    # Run every 30 seconds
    scheduler.add_job(check_for_threats, "interval", seconds=30)
    scheduler.start()
    logger.info("Autonomous background scheduler started.")
