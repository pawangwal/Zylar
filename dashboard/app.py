import time

import networkx as nx
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

from zylar.core.settings import get_settings

load_dotenv()

st.set_page_config(page_title="ZYLAR Autonomous SOC", layout="wide", page_icon="🛡️")

# Auto-refresh every 15 seconds
count = st_autorefresh(interval=15000, limit=None, key="zylar_autorefresh")

settings = get_settings()
API_URL = f"http://{settings.api_host}:{settings.api_port}"

st.title("🛡️ ZYLAR v2 – Autonomous Self-Evolving SOC AI System")

# Ensure user gets context on status
st.sidebar.markdown("### 🤖 Autonomous Mode: **ACTIVE**")
st.sidebar.markdown(f"*Last refresh: {time.strftime('%H:%M:%S')}*")
st.sidebar.markdown("---")


def escape_dot_identifier(val: str) -> str:
    """Escapes backslashes, double quotes, and newlines for safe Graphviz DOT interpolation."""
    if not val:
        return ""
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


def get_auth_token() -> str:
    if "auth_token" in st.session_state and st.session_state["auth_token"]:
        return st.session_state["auth_token"]
    try:
        res = requests.post(
            f"{API_URL}/api/auth/token",
            json={
                "username": settings.bootstrap_admin_username,
                "password": settings.bootstrap_admin_password.get_secret_value(),
            },
            timeout=settings.request_timeout_seconds,
        )
        if res.status_code == 200:
            tok = res.json().get("access_token", "")
            st.session_state["auth_token"] = tok
            return tok
    except Exception:
        pass
    return ""


token = get_auth_token()
auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

# Query real-time health checks from /health/ready
health_checks = {"elasticsearch": "offline", "database": "offline", "ollama": "offline"}
backend_online = False
try:
    h_res = requests.get(f"{API_URL}/health/ready", timeout=settings.request_timeout_seconds)
    if h_res.status_code in (200, 503):
        backend_online = True
        health_checks = h_res.json().get("checks", {})
except Exception:
    backend_online = False

st.sidebar.markdown("**System Monitor**")
es_status = health_checks.get("elasticsearch", "offline")
es_icon = "✔️" if es_status == "healthy" else "❌"
st.sidebar.markdown(f"{es_icon} **Elasticsearch**: {es_status.capitalize()}")

api_icon = "✔️" if backend_online else "❌"
st.sidebar.markdown(f"{api_icon} **FastAPI Backend**: {'Online' if backend_online else 'Offline'}")

db_status = health_checks.get("database", "offline")
db_icon = "✔️" if db_status == "healthy" else "❌"
st.sidebar.markdown(f"{db_icon} **PostgreSQL DB**: {db_status.capitalize()}")

ollama_status = health_checks.get("ollama", "offline")
ollama_icon = "✔️" if ollama_status == "healthy" else ("⚠️" if ollama_status == "degraded" else "❌")
st.sidebar.markdown(f"{ollama_icon} **Ollama Runtime**: {ollama_status.capitalize()}")
st.sidebar.markdown("✔️ **Background Scheduler**: Running (30s interval)")

tab1, tab2, tab3 = st.tabs(
    ["🔴 Real-time Dashboard", "📄 Incident Timeline", "🧠 Threat Graph & Intelligence"]
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
            f"{API_URL}/api/logs/recent?minutes=10",
            headers=auth_headers,
            timeout=settings.request_timeout_seconds,
        )
        if res.status_code == 200:
            recent_logs = res.json().get("logs", [])

        rep_res = requests.get(
            f"{API_URL}/api/reports",
            headers=auth_headers,
            timeout=settings.request_timeout_seconds,
        )
        if rep_res.status_code == 200:
            reports = rep_res.json().get("reports", [])
            attacks_count = len(reports)

        off_res = requests.get(
            f"{API_URL}/api/offenders",
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

    col_kpi1.metric(
        "Current System Risk Score", f"{latest_risk}/100", delta=None, delta_color="inverse"
    )
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

                st.subheader("Mitigation Plan (Ollama AI)")
                for step in rep.get("mitigation_plan", []):
                    st.markdown(f"- {step}")

                st.subheader("Threat Intelligence")
                st.json(rep.get("threat_intel"))
    else:
        st.info("No incidents generated by autonomous workflow yet.")

with tab3:
    st.header("Real-Time Threat Correlation Graph")
    st.markdown(
        "Displays entity relationships (IPs, Users, Ports) across the latest detected anomalies to identify highly connected attack nodes."
    )

    if recent_logs:
        # Build ephemeral graph out of failures and rare events to visualize attack network
        df = pd.DataFrame(recent_logs)
        anomalies = [
            log
            for log in recent_logs
            if log.get("status") in ["failed", "rejected"] or log.get("event_type") == "ransomware"
        ]

        if anomalies:
            G = nx.Graph()
            for event in anomalies:
                src_ip = event.get("source_ip")
                user = event.get("username", event.get("user"))
                dest_port = event.get("destination_port")

                if src_ip and user:
                    G.add_edge(f"IP:{src_ip[-8:]}", f"User:{user}", type="login")
                if src_ip and dest_port:
                    G.add_edge(f"IP:{src_ip[-8:]}", f"Port:{dest_port}", type="scan")

            if len(G.edges) > 0:
                dot = "graph {\n"
                dot += '  node [style="filled", fontname="Arial", shape="box", fillcolor="#444444", fontcolor="white", rounded="true"];\n'
                dot += '  edge [color="#888888"];\n'
                for u, v in G.edges():
                    dot += f'  "{escape_dot_identifier(str(u))}" -- "{escape_dot_identifier(str(v))}";\n'
                dot += "}"

                st.graphviz_chart(dot)

                # Centrality metrics
                deg = nx.degree_centrality(G)
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
