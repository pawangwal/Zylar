from __future__ import annotations

import logging
from typing import Any, Dict
import networkx as nx
from agents.state import AgentState

logger = logging.getLogger(__name__)

# Operational bounds to prevent unbounded memory usage or algorithmic blowup
MAX_CORRELATION_EVENTS = 500
MAX_GRAPH_NODES = 250
MAX_GRAPH_EDGES = 600


def build_threat_correlation_graph_node(state: AgentState) -> Dict[str, Any]:
    """Uses NetworkX to build an attack graph from log events and identify highly connected entities."""
    events = state.get("anomalies", [])
    if not events:
        return {"graph_centrality": 0.0}

    G = nx.Graph()

    # Bound the input events considered for correlation
    bounded_events = events[:MAX_CORRELATION_EVENTS]
    if len(events) > MAX_CORRELATION_EVENTS:
        logger.warning(
            "Correlation events bounded from %d to %d",
            len(events),
            MAX_CORRELATION_EVENTS,
        )

    # Add edges based on log activity using canonical fields
    for event in bounded_events:
        if G.number_of_nodes() >= MAX_GRAPH_NODES or G.number_of_edges() >= MAX_GRAPH_EDGES:
            logger.warning(
                "Correlation graph hit resource limits: nodes=%d, edges=%d",
                G.number_of_nodes(),
                G.number_of_edges(),
            )
            break

        src_ip = event.get("source_ip")
        # Canonical 'user' identity with fallback to legacy 'username'
        user = event.get("user") or event.get("username")
        dest_port = event.get("destination_port")
        if dest_port is not None:
            try:
                dest_port = int(dest_port)
            except (ValueError, TypeError):
                dest_port = None

        if src_ip and user:
            # Login action binds IP to User
            G.add_edge(f"IP:{src_ip}", f"User:{user}", weight=1, type="login_attempt")

        if src_ip and dest_port is not None:
            # IP attacking a specific port/service
            G.add_edge(f"IP:{src_ip}", f"Port:{dest_port}", weight=1, type="scan")

    if G.number_of_nodes() == 0:
        return {"graph_centrality": 0.0}

    # Calculate degree centrality - how connected a node is
    deg_centrality = nx.degree_centrality(G)

    # Calculate betweenness centrality - paths going through node
    try:
        bet_centrality = nx.betweenness_centrality(G)
    except Exception as exc:
        logger.debug("Betweenness centrality calculation failed, defaulting to 0.0: %s", exc)
        bet_centrality = {node: 0.0 for node in G.nodes}

    max_centrality_score = 0.0
    for node in G.nodes:
        # Combine degree and betweenness for an overall importance score for the node
        score = (deg_centrality.get(node, 0.0) * 0.6) + (bet_centrality.get(node, 0.0) * 0.4)
        if score > max_centrality_score:
            max_centrality_score = score

    # Normalize our custom max score into a heuristic 0-100 metric
    normalized_centrality = min(100.0, max_centrality_score * 100 * 5)

    return {"graph_centrality": normalized_centrality}
