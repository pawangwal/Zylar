"""Zylar Autonomous SOC Dashboard — Real-time telemetry, threat intelligence, and observability."""

from __future__ import annotations

import re
import time
from typing import Any

import networkx as nx
import pandas as pd
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from zylar.core.settings import get_settings


def escape_dot_identifier(val: str) -> str:
    """Escapes backslashes, double quotes, and newlines for safe Graphviz DOT interpolation."""
    if not val:
        return ""
    # Strip potential DOT / SQL injection payload delimiters
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
    """Fetches dependency health status from GET /health/ready with graceful fallback."""
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
    except Exception as exc:
        return {
            "status": "unreachable",
            "checks": {"elasticsearch": "offline", "database": "offline", "ollama": "offline"},
            "timestamp": None,
            "reachable": False,
            "error": str(exc),
        }


def fetch_ingestion_status(
    api_url: str, auth_headers: dict[str, str], timeout: float = 3.0
) -> dict[str, Any]:
    """Queries /api/ingestion/status for checkpoint watermark and lag metrics."""
    url = f"{api_url.rstrip('/')}/api/ingestion/status"
    try:
        res = requests.get(url, headers=auth_headers, timeout=timeout)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "error": f"HTTP {res.status_code}"}
    except Exception as exc:
        return {"status": "unreachable", "error": str(exc)}


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


def parse_prometheus_metrics(metrics_text: str) -> dict[str, Any]:
    """Parses key Prometheus counters from exposition text for UI meters."""
    metrics: dict[str, Any] = {
        "ingested_total": 0,
        "deduplicated_total": 0,
        "workflows": {},
        "rules_fired": {},
    }
    if not metrics_text:
        return metrics

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

        if key == "zylar_ingested_events_total":
            metrics["ingested_total"] = val
        elif key == "zylar_deduplicated_events_total":
            metrics["deduplicated_total"] = val
        elif key.startswith('zylar_workflow_executions_total{status="'):
            st_name = key.split('status="')[1].split('"}')[0]
            metrics["workflows"][st_name] = val
        elif key.startswith('zylar_detection_rules_fired_total{rule="'):
            rule_name = key.split('rule="')[1].split('"}')[0]
            metrics["rules_fired"][rule_name] = val

    return metrics


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

    # Context and metadata
    st.sidebar.markdown("### 🤖 Autonomous Mode: **ACTIVE**")
    st.sidebar.markdown(f"*Last refresh: {time.strftime('%H:%M:%S')}*")
    st.sidebar.markdown("---")

    # Authentication
    token = get_auth_token(
        api_url=api_url,
        username=settings.bootstrap_admin_username,
        password=settings.bootstrap_admin_password.get_secret_value(),
        timeout=settings.request_timeout_seconds,
    )
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    # Query operational health from /health/ready
    health_data = fetch_backend_health(api_url, timeout=settings.request_timeout_seconds)
    backend_status = health_data.get("status", "unreachable")
    checks = health_data.get("checks", {})

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
    st.sidebar.markdown("✔️ **Autonomous Scheduler**: Active (30s interval)")

    # Fetch Prometheus Metrics
    prom_raw = fetch_metrics(api_url, timeout=settings.request_timeout_seconds)
    prom_metrics = parse_prometheus_metrics(prom_raw)

    # Fetch Ingestion Watermark and Checkpoint Lag
    ingestion_data = fetch_ingestion_status(api_url, auth_headers, timeout=settings.request_timeout_seconds)

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

        # Fetch Data
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

        latest_risk = 0
        if reports:
            latest_risk = reports[0].get("risk_score", 0)

        col_kpi1.metric("Current System Risk Score", f"{latest_risk}/100", delta=None, delta_color="inverse")
        col_kpi2.metric("Incidents Logged", str(attacks_count))
        col_kpi3.metric("Logs Monitored (10m)", str(len(recent_logs)))

        st.markdown("---")

        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.subheader("Recurring Offenders (Persistent Memory)")
            if top_ips:
                df_ips = pd.DataFrame(top_ips)
                st.markdown("**Top Suspicious IPs**")
                st.dataframe(df_ips, use_container_width=True)
            else:
                st.info("No recurring IP threats in memory.")

            if top_users:
                df_users = pd.DataFrame(top_users)
                st.markdown("**Top Compromised/Malicious Users**")
                st.dataframe(df_users, use_container_width=True)

        with col_right:
            st.subheader("Live Event Distribution")
            if recent_logs:
                df_logs = pd.DataFrame(recent_logs)
                event_counts = df_logs["event_type"].value_counts()
                st.bar_chart(event_counts)
            else:
                st.info("No live logs detected.")

    with tab2:
        st.header("📊 Prometheus Observability & Ingestion Telemetry")

        col_obs1, col_obs2, col_obs3, col_obs4 = st.columns(4)
        col_obs1.metric("Ingested Events Total", str(prom_metrics["ingested_total"]))
        col_obs2.metric("Deduplicated Events", str(prom_metrics["deduplicated_total"]))

        lag_display = (
            f"{ingestion_data.get('lag_seconds', 0.0):.1f}s"
            if ingestion_data.get("lag_seconds") is not None
            else "N/A"
        )
        col_obs3.metric("Checkpoint Watermark Lag", lag_display)
        col_obs4.metric("Dead-Letter Queue", str(ingestion_data.get("dead_letters_count", 0)))

        st.markdown("---")
        st.subheader("Deterministic Detection Rules Fired")
        rules_fired = prom_metrics.get("rules_fired", {})
        if rules_fired:
            df_rules = pd.DataFrame(
                [{"Rule Identifier": r, "Trigger Count": cnt} for r, cnt in sorted(rules_fired.items())]
            )
            st.dataframe(df_rules, use_container_width=True)
        else:
            st.info("No detection rules triggered in current metric epoch.")

        st.subheader("Autonomous Workflow Executions")
        wf_counts = prom_metrics.get("workflows", {})
        if wf_counts:
            col_w1, col_w2 = st.columns(2)
            col_w1.metric("Workflows Completed (Success)", str(wf_counts.get("success", 0)))
            col_w2.metric("Workflows Failed", str(wf_counts.get("failed", 0)))
        else:
            st.info("No workflow executions recorded yet.")

    with tab3:
        st.header("Autonomous Incident Timeline")
        if reports:
            for rep in reports:
                risk = rep.get("risk_score", 0)
                color = "🔴" if risk >= 80 else "🟠" if risk >= 60 else "🟡" if risk >= 40 else "🟢"

                with st.expander(
                    f"{color} {rep.get('timestamp')} | {rep.get('attack_classification')} (Risk: {risk}/100)"
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
            "Displays entity relationships (IPs, Users, Ports) across the latest detected anomalies to identify highly connected attack nodes."
        )

        if recent_logs:
            anomalies = [
                log
                for log in recent_logs
                if log.get("status") in ["failed", "rejected"] or log.get("event_type") == "ransomware"
            ]

            if anomalies:
                g = nx.Graph()
                for event in anomalies:
                    src_ip = event.get("source_ip")
                    user = event.get("username", event.get("user"))
                    dest_port = event.get("destination_port")

                    if src_ip and user:
                        g.add_edge(f"IP:{src_ip[-8:]}", f"User:{user}", type="login")
                    if src_ip and dest_port:
                        g.add_edge(f"IP:{src_ip[-8:]}", f"Port:{dest_port}", type="scan")

                if len(g.edges) > 0:
                    dot = "graph {\n"
                    dot += '  node [style="filled", fontname="Arial", shape="box", fillcolor="#444444", fontcolor="white", rounded="true"];\n'
                    dot += '  edge [color="#888888"];\n'
                    for u, v in g.edges():
                        dot += f'  "{escape_dot_identifier(str(u))}" -- "{escape_dot_identifier(str(v))}";\n'
                    dot += "}"

                    st.graphviz_chart(dot)

                    # Centrality metrics
                    deg = nx.degree_centrality(g)
                    top_nodes = sorted(deg.items(), key=lambda x: x[1], reverse=True)[:5]
                    st.markdown("**Top Highly Connected Entities (Graph Centrality)**")
                    for node, score in top_nodes:
                        st.markdown(f"- **{node}**: {score:.2f}")
                else:
                    st.info("Not enough correlatable data in current anomalies to build graph.")
            else:
                st.success("No anomalies detected in recent log batch.")
        else:
            st.info("No logs available to visualize.")


if __name__ == "__main__":
    main()
