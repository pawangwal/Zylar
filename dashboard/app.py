"""Zylar Autonomous SOC Dashboard — Real-time telemetry, threat intelligence, and observability.

Operational Constraints & Boundaries:
- In production multi-user deployments, operators authenticate interactively with least-privilege credentials.
- In local single-user sandbox development, credentials default to configured bootstrap administrator settings.
- Threat graph visualization strictly renders bounded canonical output from the Task 3 correlation service (/api/threat-graph).
- Unavailable metrics are explicitly marked as 'Unavailable' rather than showing misleading zero counters.
"""

from __future__ import annotations

import re
import time
from typing import Any

import pandas as pd
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from zylar.analysis.risk_scoring import DEFAULT_RISK_POLICY
from zylar.core.settings import get_settings


def escape_dot_identifier(val: str) -> str:
    """Escapes backslashes, double quotes, and newlines for safe Graphviz DOT interpolation."""
    if not val:
        return ""
    sanitized = re.sub(
        r";\s*(?:drop|delete|insert|update|alter|exec)\b.*", "", str(val), flags=re.IGNORECASE
    )
    return (
        sanitized.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def fetch_backend_health(api_url: str, timeout: float = 3.0) -> dict[str, Any]:
    """Fetches dependency health status from GET /health/ready with sanitized error reporting."""
    url = f"{api_url.rstrip('/')}/health/ready"
    try:
        res = requests.get(url, timeout=timeout)
        if res.status_code in (200, 503):
            data = res.json()
            return {
                "status": data.get("status", "unhealthy"),
                "checks": data.get("checks", {}),
                "timestamp": data.get("timestamp"),
                "reachable": True,
            }
        return {
            "status": "unhealthy",
            "checks": {},
            "timestamp": None,
            "reachable": True,
            "error": f"HTTP {res.status_code}",
        }
    except requests.Timeout:
        return {
            "status": "unreachable",
            "checks": {"elasticsearch": "offline", "database": "offline", "ollama": "offline"},
            "timestamp": None,
            "reachable": False,
            "error": "Backend connection timed out",
        }
    except Exception:
        return {
            "status": "unreachable",
            "checks": {"elasticsearch": "offline", "database": "offline", "ollama": "offline"},
            "timestamp": None,
            "reachable": False,
            "error": "Failed to connect to backend service",
        }


def fetch_ingestion_status(
    api_url: str, auth_headers: dict[str, str], timeout: float = 3.0
) -> dict[str, Any]:
    """Queries /api/ingestion/status for checkpoint watermark, scheduler health, and lag metrics."""
    url = f"{api_url.rstrip('/')}/api/ingestion/status"
    try:
        res = requests.get(url, headers=auth_headers, timeout=timeout)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "error": f"HTTP {res.status_code}"}
    except requests.Timeout:
        return {"status": "unreachable", "error": "Ingestion status request timeout"}
    except Exception:
        return {"status": "unreachable", "error": "Unable to query ingestion status from backend"}


def fetch_metrics(api_url: str, timeout: float = 3.0) -> str:
    """Queries GET /metrics for Prometheus operational metrics exposition."""
    url = f"{api_url.rstrip('/')}/metrics"
    try:
        res = requests.get(url, timeout=timeout)
        if res.status_code == 200:
            return res.text
        return ""
    except Exception:
        return ""


def parse_prometheus_metrics(metrics_text: str | None) -> dict[str, Any]:
    """Parses Prometheus lifecycle counters from exposition text for UI meters.

    Explicitly returns status='unavailable' when metrics cannot be fetched,
    preventing misleading zero readings on service failure.
    """
    if not metrics_text or not metrics_text.strip():
        return {
            "status": "unavailable",
            "events_received": None,
            "events_processed": None,
            "events_deduplicated": None,
            "events_quarantined": None,
            "workflow_events_completed": None,
            "incidents_persisted": None,
            "checkpoint_advances": None,
            "ingested_total": None,
            "deduplicated_total": None,
            "workflows": {},
            "rules_fired": {},
        }

    metrics: dict[str, Any] = {
        "status": "available",
        "events_received": 0,
        "events_processed": 0,
        "events_deduplicated": 0,
        "events_quarantined": 0,
        "workflow_events_completed": 0,
        "incidents_persisted": 0,
        "checkpoint_advances": 0,
        "ingested_total": 0,
        "deduplicated_total": 0,
        "workflows": {},
        "rules_fired": {},
    }

    for line in metrics_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        key, val_str = parts[0], parts[1]
        try:
            val = float(val_str)
            if val.is_integer():
                val = int(val)
        except ValueError:
            continue

        if key in ("zylar_events_received_total", "zylar_ingested_events_total"):
            metrics["events_received"] = val
            metrics["ingested_total"] = val
        elif key == "zylar_events_processed_total":
            metrics["events_processed"] = val
        elif key in ("zylar_events_deduplicated_total", "zylar_deduplicated_events_total"):
            metrics["events_deduplicated"] = val
            metrics["deduplicated_total"] = val
        elif key == "zylar_events_quarantined_total":
            metrics["events_quarantined"] = val
        elif key == "zylar_workflow_events_completed_total":
            metrics["workflow_events_completed"] = val
        elif key == "zylar_incidents_persisted_total":
            metrics["incidents_persisted"] = val
        elif key == "zylar_ingestion_checkpoint_advances_total":
            metrics["checkpoint_advances"] = val
        elif key.startswith('zylar_workflow_executions_total{status="'):
            st_name = key.split('status="')[1].split('"}')[0]
            metrics["workflows"][st_name] = val
        elif key.startswith('zylar_detection_rules_fired_total{rule="'):
            rule_name = key.split('rule="')[1].split('"}')[0]
            metrics["rules_fired"][rule_name] = val

    return metrics


def fetch_threat_graph(
    api_url: str, auth_headers: dict[str, str], minutes: int = 15, timeout: float = 5.0
) -> dict[str, Any]:
    """Retrieves the canonical bounded threat correlation graph from GET /api/threat-graph."""
    url = f"{api_url.rstrip('/')}/api/threat-graph?minutes={minutes}"
    try:
        res = requests.get(url, headers=auth_headers, timeout=timeout)
        if res.status_code == 200:
            data = res.json()
            data["status"] = "available"
            return data
        return {
            "status": "unavailable",
            "error": f"Search backend failure (HTTP {res.status_code})",
            "dot_graph": "",
            "top_entities": [],
            "centrality_score": 0.0,
            "total_nodes": 0,
            "total_edges": 0,
            "truncated": False,
        }
    except requests.Timeout:
        return {
            "status": "unavailable",
            "error": "Threat graph request timed out",
            "dot_graph": "",
            "top_entities": [],
            "centrality_score": 0.0,
            "total_nodes": 0,
            "total_edges": 0,
            "truncated": False,
        }
    except Exception:
        return {
            "status": "unavailable",
            "error": "Failed to connect to threat graph endpoint",
            "dot_graph": "",
            "top_entities": [],
            "centrality_score": 0.0,
            "total_nodes": 0,
            "total_edges": 0,
            "truncated": False,
        }


def get_auth_token(api_url: str, username: str, password: str, timeout: float = 3.0) -> str:
    """Obtains a JWT bearer token for authenticated API requests."""
    if "auth_token" in st.session_state and st.session_state["auth_token"]:
        return str(st.session_state["auth_token"])
    try:
        res = requests.post(
            f"{api_url.rstrip('/')}/api/auth/token",
            json={"username": username, "password": password},
            timeout=timeout,
        )
        if res.status_code == 200:
            tok = res.json().get("access_token", "")
            st.session_state["auth_token"] = tok
            return str(tok)
    except Exception:
        pass
    return ""


def main() -> None:
    st.set_page_config(page_title="ZYLAR Autonomous SOC", layout="wide", page_icon="🛡️")

    # Auto-refresh every 15 seconds
    st_autorefresh(interval=15000, limit=None, key="zylar_autorefresh")

    settings = get_settings()
    api_url = f"http://{settings.api_host}:{settings.api_port}"

    st.title("🛡️ ZYLAR v2 – Autonomous Self-Evolving SOC AI System")

    # Authentication credentials: allow interactive login with bootstrap fallback for local dev
    st.sidebar.markdown("### 🔐 SOC Operator Access")
    username = st.sidebar.text_input(
        "Username",
        value=settings.bootstrap_admin_username,
        key="login_user",
    )
    password = st.sidebar.text_input(
        "Password",
        value=settings.bootstrap_admin_password.get_secret_value(),
        type="password",
        key="login_pass",
    )

    token = get_auth_token(
        api_url=api_url,
        username=username,
        password=password,
        timeout=settings.request_timeout_seconds,
    )
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    # Query operational health from /health/ready
    health_data = fetch_backend_health(api_url, timeout=settings.request_timeout_seconds)
    backend_status = health_data.get("status", "unreachable")
    checks = health_data.get("checks", {})

    # Fetch Ingestion Watermark and Checkpoint Lag
    ingestion_data = fetch_ingestion_status(
        api_url, auth_headers, timeout=settings.request_timeout_seconds
    )
    scheduler_info = ingestion_data.get("scheduler", {})
    scheduler_running = scheduler_info.get("running", False)
    scheduler_status_str = scheduler_info.get("status", "unknown")

    # Autonomous Mode Status derived truthfully from verified backend state
    if not health_data["reachable"]:
        autonomous_mode_text = "**OFFLINE**"
    elif scheduler_running:
        autonomous_mode_text = "**ACTIVE**"
    else:
        autonomous_mode_text = f"**{scheduler_status_str.upper()}**"

    st.sidebar.markdown(f"### 🤖 Autonomous Mode: {autonomous_mode_text}")
    st.sidebar.markdown(f"*Last refresh: {time.strftime('%H:%M:%S')}*")
    st.sidebar.markdown("---")

    # System Status Banner
    if backend_status == "ready":
        st.success("🟢 **System Operational**: All dependencies (PostgreSQL, Elasticsearch) healthy.")
    elif backend_status == "degraded":
        st.warning("🟡 **System Degraded**: Core services up; optional LLM offline with deterministic fallback active.")
    else:
        st.error("🔴 **System Unhealthy / Unreachable**: Backend API or critical storage dependency unavailable.")

    # Sidebar System Monitor
    st.sidebar.markdown("**System Monitor**")
    es_status = checks.get("elasticsearch", "offline")
    es_icon = "✔️" if es_status == "healthy" else "❌"
    st.sidebar.markdown(f"{es_icon} **Elasticsearch**: {es_status.capitalize()}")

    api_icon = "✔️" if health_data["reachable"] else "❌"
    st.sidebar.markdown(f"{api_icon} **FastAPI Backend**: {'Online' if health_data['reachable'] else 'Offline'}")

    db_status = checks.get("database", "offline")
    db_icon = "✔️" if db_status == "healthy" else "❌"
    st.sidebar.markdown(f"{db_icon} **PostgreSQL DB**: {db_status.capitalize()}")

    ollama_status = checks.get("ollama", "offline")
    ollama_icon = "✔️" if ollama_status == "healthy" else ("⚠️" if ollama_status == "degraded" else "❌")
    st.sidebar.markdown(f"{ollama_icon} **Ollama Runtime**: {ollama_status.capitalize()}")

    sched_icon = "✔️" if scheduler_running else ("⚠️" if scheduler_status_str == "stopped" else "❌")
    st.sidebar.markdown(f"{sched_icon} **Autonomous Scheduler**: {scheduler_status_str.capitalize()}")

    # Ingestion Worker Status (queried from PostgreSQL worker_instances via /api/ingestion/status)
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Ingestion Worker Status**")
    active_workers = ingestion_data.get("active_workers", [])
    if active_workers:
        for w in active_workers:
            w_name = w.get("worker_name", "worker")
            w_status = str(w.get("status", "UNKNOWN")).upper()
            w_lag = w.get("heartbeat_lag_seconds")
            w_host = w.get("hostname", "unknown")
            is_healthy = w_status == "ACTIVE" and (w_lag is None or w_lag <= 30.0)
            w_icon = "✔️" if is_healthy else "⚠️"
            st.sidebar.markdown(f"{w_icon} **{w_name}** (`{w_status}`)")
            st.sidebar.caption(
                f"Host: `{w_host}` | Lag: `{f'{w_lag:.1f}s' if w_lag is not None else 'N/A'}`"
            )
            if w_lag is not None and w_lag > 30.0:
                st.sidebar.warning(
                    f"⚠️ Worker `{w_name}` heartbeat lag ({w_lag:.1f}s) exceeds 30s threshold!"
                )
    else:
        st.sidebar.caption("No dedicated workers registered in PostgreSQL.")

    lease_owner = ingestion_data.get("lease_owner")
    lease_gen = ingestion_data.get("lease_generation")
    if lease_owner:
        st.sidebar.caption(f"Lease Owner: `{lease_owner}` (Gen {lease_gen})")

    # Fetch Prometheus Metrics
    prom_raw = fetch_metrics(api_url, timeout=settings.request_timeout_seconds)
    prom_metrics = parse_prometheus_metrics(prom_raw)

    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "🔴 Real-time Dashboard",
            "📊 SOC Observability & Metrics",
            "📄 Incident Timeline",
            "🧠 Threat Graph & Intelligence",
        ]
    )

    with tab1:
        col_kpi1, col_kpi2, col_kpi3 = st.columns(3)

        recent_logs = []
        attacks_count = 0
        top_ips = []
        top_users = []
        reports = []

        try:
            res = requests.get(
                f"{api_url}/api/logs/recent?minutes=10",
                headers=auth_headers,
                timeout=settings.request_timeout_seconds,
            )
            if res.status_code == 200:
                recent_logs = res.json().get("logs", [])

            rep_res = requests.get(
                f"{api_url}/api/reports",
                headers=auth_headers,
                timeout=settings.request_timeout_seconds,
            )
            if rep_res.status_code == 200:
                reports = rep_res.json().get("reports", [])
                attacks_count = len(reports)

            off_res = requests.get(
                f"{api_url}/api/offenders",
                headers=auth_headers,
                timeout=settings.request_timeout_seconds,
            )
            if off_res.status_code == 200:
                data = off_res.json().get("data", {})
                top_ips = data.get("top_ips", [])
                top_users = data.get("top_users", [])

        except Exception as e:
            st.error(f"Error connecting to backend API: {e}")

        with col_kpi1:
            st.metric("Recent Logs (10m)", len(recent_logs))
        with col_kpi2:
            st.metric("Detected Incidents", attacks_count)
        with col_kpi3:
            st.metric("Known Malicious IPs", len(top_ips))

        st.subheader("🔥 Top Malicious Offenders")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Top Source IPs by Failed/Rejected Activity**")
            if top_ips:
                st.dataframe(pd.DataFrame(top_ips), use_container_width=True)
            else:
                st.info("No offender IP records in database.")
        with c2:
            st.markdown("**Top Targeted Users by Failed Activity**")
            if top_users:
                st.dataframe(pd.DataFrame(top_users), use_container_width=True)
            else:
                st.info("No offender user records in database.")

    with tab2:
        st.header("SOC Ingestion & Prometheus Metrics")
        st.markdown(
            "Operational telemetry from checkpointed ingestion worker and SOC detection rules."
        )

        st.subheader("Checkpoint Ingestion Status")
        col_ing1, col_ing2, col_ing3, col_ing4 = st.columns(4)

        watermark_ts = ingestion_data.get("last_processed_timestamp") or "None"
        lag_sec = ingestion_data.get("lag_seconds")
        lag_display = f"{lag_sec:.1f}s" if lag_sec is not None else "N/A"
        events_processed = ingestion_data.get("events_processed_count", 0)
        dead_letters = ingestion_data.get("dead_letters_count", 0)

        col_ing1.metric("Watermark Timestamp", str(watermark_ts)[:19])
        col_ing2.metric("Ingestion Lag", lag_display)
        col_ing3.metric("Events Processed (DB)", events_processed)
        col_ing4.metric("Quarantined Dead Letters", dead_letters)

        st.subheader("Prometheus Operational Counters")
        if prom_metrics.get("status") == "unavailable":
            st.warning("⚠️ Operational metrics telemetry currently unavailable (cannot connect to /metrics).")
        else:
            col_pm1, col_pm2, col_pm3, col_pm4 = st.columns(4)
            col_pm1.metric("Events Received (Boundary)", prom_metrics["events_received"])
            col_pm2.metric("Events Processed (Durable)", prom_metrics["events_processed"])
            col_pm3.metric("Events Deduplicated", prom_metrics["events_deduplicated"])
            col_pm4.metric("Events Quarantined", prom_metrics["events_quarantined"])

            col_pm5, col_pm6, col_pm7 = st.columns(3)
            col_pm5.metric(
                "Workflow Events Completed", prom_metrics.get("workflow_events_completed", 0)
            )
            col_pm6.metric(
                "Incidents Persisted (PostgreSQL)", prom_metrics.get("incidents_persisted", 0)
            )
            col_pm7.metric(
                "Checkpoint Advances (PostgreSQL)", prom_metrics.get("checkpoint_advances", 0)
            )

        st.subheader("Deterministic SOC Rules Triggered")
        rules_map = prom_metrics.get("rules_fired", {})
        if rules_map:
            rules_df = pd.DataFrame(
                [{"Rule Identifier": r, "Triggers Count": cnt} for r, cnt in rules_map.items()]
            )
            st.dataframe(rules_df, use_container_width=True)
        else:
            if prom_metrics.get("status") == "available":
                st.info("No detection rules triggered in current metric epoch.")

        st.subheader("Autonomous Workflow Executions")
        wf_counts = prom_metrics.get("workflows", {})
        if wf_counts:
            col_w1, col_w2 = st.columns(2)
            col_w1.metric("Workflows Completed (Success)", str(wf_counts.get("success", 0)))
            col_w2.metric("Workflows Failed", str(wf_counts.get("failed", 0)))
        else:
            if prom_metrics.get("status") == "available":
                st.info("No workflow executions recorded yet.")

    with tab3:
        st.header("Autonomous Incident Timeline")
        if reports:
            for rep in reports:
                risk = rep.get("risk_score", 0)
                category = rep.get("risk_category") or DEFAULT_RISK_POLICY.get_category_for_score(risk)
                color_map = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🟢",
                }
                color = color_map.get(category, "⚪")

                with st.expander(
                    f"{color} {rep.get('timestamp')} | {rep.get('attack_classification')} ({category} - Risk: {risk}/100)"
                ):
                    st.markdown(f"**Incident ID:** `{rep.get('incident_id')}`")
                    st.markdown(f"**Anomalous Events Triaged:** {rep.get('anomalous_events_count')}")
                    if rep.get("risk_policy_version"):
                        st.markdown(f"**Risk Policy Version:** `{rep.get('risk_policy_version')}`")

                    st.subheader("Mitigation Plan (Ollama AI / Fallback)")
                    for step in rep.get("mitigation_plan", []):
                        st.markdown(f"- {step}")

                    st.subheader("Threat Intelligence")
                    st.json(rep.get("threat_intel"))
        else:
            st.info("No incidents generated by autonomous workflow yet.")

    with tab4:
        st.header("Real-Time Threat Correlation Graph")
        st.markdown(
            "Visualizes canonical entity relationships (IPs, Users, Destination Ports) "
            "and degree/betweenness centrality computed by the bounded SOC Correlation Service."
        )

        graph_data = fetch_threat_graph(
            api_url=api_url,
            auth_headers=auth_headers,
            minutes=15,
            timeout=settings.request_timeout_seconds,
        )

        if graph_data.get("status") == "unavailable":
            st.error(f"🔴 Threat Graph Unavailable: {graph_data.get('error', 'Unable to query backend')}")
        else:
            dot_graph = graph_data.get("dot_graph", "")
            top_entities = graph_data.get("top_entities", [])
            centrality_score = graph_data.get("centrality_score", 0.0)
            total_nodes = graph_data.get("total_nodes", 0)
            total_edges = graph_data.get("total_edges", 0)
            truncated = graph_data.get("truncated", False)

            c_g1, c_g2, c_g3 = st.columns(3)
            c_g1.metric("Graph Entities (Nodes)", total_nodes)
            c_g2.metric("Correlated Links (Edges)", total_edges)
            c_g3.metric("Max Centrality Score", f"{centrality_score:.1f}/100")

            if truncated:
                reasons = []
                if graph_data.get("event_limit_reached"):
                    reasons.append(f"events capped at 500 (from {graph_data.get('input_event_count', 0)})")
                if graph_data.get("node_limit_reached"):
                    reasons.append("node limit reached (250)")
                if graph_data.get("edge_limit_reached"):
                    reasons.append("edge limit reached (600)")
                reason_str = ", ".join(reasons) or "safety bounds exceeded"
                st.warning(f"⚠️ Threat graph bounded: {reason_str}.")

            if dot_graph and total_nodes > 0:
                st.graphviz_chart(dot_graph)
                if top_entities:
                    st.markdown("**Top Highly Connected Entities (Graph Centrality)**")
                    for ent in top_entities:
                        st.markdown(f"- `{ent}`")
            else:
                st.info("No active threat relationships to display in the current time window.")


if __name__ == "__main__":
    main()
