from __future__ import annotations

import logging
from typing import Any

from agents.state import AgentState
from zylar.analysis.correlation_service import (
    build_correlation_graph,
)

logger = logging.getLogger(__name__)

# Re-export bounds for backwards compatibility with existing imports
MAX_GRAPH_NODES = 250
MAX_GRAPH_EDGES = 600


def build_threat_correlation_graph_node(state: AgentState) -> dict[str, Any]:
    """Uses build_correlation_graph to construct an attack graph from log events,
    identify highly connected entities, and produce safe DOT visualizations.
    """
    events = state.get("anomalies", [])
    if not events:
        return {"graph_centrality": 0.0}

    result = build_correlation_graph(
        events,
        max_nodes=MAX_GRAPH_NODES,
        max_edges=MAX_GRAPH_EDGES,
    )

    return {
        "graph_centrality": result.centrality_score,
        "graph_nodes_count": result.node_count,
        "graph_edges_count": result.edge_count,
        "top_connected_entities": result.top_entities,
        "graphviz_dot": result.dot_representation,
    }
