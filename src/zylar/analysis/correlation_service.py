from __future__ import annotations

import logging
import re
from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict

from zylar.analysis.risk_scoring import parse_valid_port

logger = logging.getLogger(__name__)

MAX_CORRELATION_EVENTS = 500


def _escape_dot_label(text: str) -> str:
    """Escapes backslashes, quotes, and newlines for DOT syntax, and sanitizes injection patterns."""
    if not text:
        return ""
    # Strip potential DOT / script injection statements
    sanitized = re.sub(
        r";\s*(?:drop|delete|insert|update|alter|exec)\b.*",
        "",
        text,
        flags=re.IGNORECASE,
    )
    return (
        sanitized.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


class CorrelationGraphResult(BaseModel):
    """Immutable outcome of correlation graph construction and centrality scoring."""

    model_config = ConfigDict(frozen=True)

    centrality_score: float
    node_count: int
    edge_count: int
    top_entities: list[str]
    dot_representation: str


def build_correlation_graph(
    events: list[dict[str, Any]],
    max_nodes: int = 250,
    max_edges: int = 600,
) -> CorrelationGraphResult:
    """Constructs a bounded NetworkX graph and exports safe, sanitized DOT markup."""
    if not events:
        return CorrelationGraphResult(
            centrality_score=0.0,
            node_count=0,
            edge_count=0,
            top_entities=[],
            dot_representation="strict graph ThreatGraph { node [shape=box]; }",
        )

    g: nx.Graph = nx.Graph()
    bounded_events = events[:MAX_CORRELATION_EVENTS]
    if len(events) > MAX_CORRELATION_EVENTS:
        logger.warning(
            "Correlation events bounded from %d to %d",
            len(events),
            MAX_CORRELATION_EVENTS,
        )

    def _safe_add_edge(u: str, v: str, edge_type: str) -> bool:
        if g.number_of_edges() >= max_edges:
            return False
        new_nodes = (0 if u in g else 1) + (0 if v in g else 1)
        if g.number_of_nodes() + new_nodes > max_nodes:
            return False
        g.add_edge(u, v, type=edge_type)
        return True

    for e in bounded_events:
        if not isinstance(e, dict):
            continue
        if g.number_of_nodes() >= max_nodes or g.number_of_edges() >= max_edges:
            logger.warning(
                "Correlation graph hit resource limits: nodes=%d, edges=%d",
                g.number_of_nodes(),
                g.number_of_edges(),
            )
            break

        src_ip = e.get("source_ip")
        user = e.get("user") or e.get("username")
        dest_port = parse_valid_port(e.get("destination_port"))

        if src_ip and user:
            if not _safe_add_edge(f"IP:{src_ip}", f"User:{user}", "login"):
                break
        if src_ip and dest_port is not None:
            if not _safe_add_edge(f"IP:{src_ip}", f"Port:{dest_port}", "probe"):
                break

    if g.number_of_nodes() == 0:
        return CorrelationGraphResult(
            centrality_score=0.0,
            node_count=0,
            edge_count=0,
            top_entities=[],
            dot_representation="strict graph ThreatGraph { node [shape=box]; }",
        )

    deg = nx.degree_centrality(g)
    try:
        bet = nx.betweenness_centrality(g)
    except Exception:
        bet = {n: 0.0 for n in g.nodes}

    scores = {n: (deg.get(n, 0.0) * 0.6) + (bet.get(n, 0.0) * 0.4) for n in g.nodes}
    top_nodes = sorted(scores.keys(), key=lambda n: scores[n], reverse=True)[:5]
    max_score = max(scores.values()) if scores else 0.0

    # Build safe DOT representation
    lines = [
        "strict graph ThreatGraph {",
        '    node [shape=box, style=filled, fillcolor="#f0f4f8"];',
    ]
    for u, v in g.edges():
        esc_u = _escape_dot_label(str(u))
        esc_v = _escape_dot_label(str(v))
        lines.append(f'    "{esc_u}" -- "{esc_v}";')
    lines.append("}")

    return CorrelationGraphResult(
        centrality_score=round(max_score * 100.0, 2),
        node_count=g.number_of_nodes(),
        edge_count=g.number_of_edges(),
        top_entities=top_nodes,
        dot_representation="\n".join(lines),
    )
