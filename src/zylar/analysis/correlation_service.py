"""Threat correlation service extracting graph topology and computing centrality scores."""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field

from zylar.analysis.detection_rules import parse_valid_port

logger = logging.getLogger(__name__)

MAX_CORRELATION_EVENTS: int = 500


def _escape_dot_label(val: str) -> str:
    """Escapes backslashes, double quotes, and control chars for safe Graphviz DOT interpolation.

    Preserves the full entity identifier as data without destructive keyword stripping,
    preventing DOT syntax breakout while retaining complete fidelity for legitimate entities.
    """
    if not val:
        return ""

    s = str(val)
    # 1. Escape backslashes first so subsequent escapes aren't corrupted
    s = s.replace("\\", "\\\\")
    # 2. Escape double quotes so string literals cannot break out of "..."
    s = s.replace('"', '\\"')
    # 3. Escape standard control characters to their C-style DOT equivalents
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    # 4. Remove unprintable control characters (ASCII 0x00-0x1F except \t, \n, \r, and 0x7F-0x9F)
    # to protect Graphviz lexers and terminals from escape-sequence injection
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)

    return s


def _bound_entity(prefix: str, val: Any) -> str:
    """Safely bounds entity strings to 128 characters preserving uniqueness via sha256 suffix."""
    s = str(val).strip() if val is not None else ""
    full_str = f"{prefix}:{s}"
    if len(full_str) <= 128:
        return full_str
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    truncated = full_str[:119]
    return f"{truncated}_{digest}"


class CorrelationGraphResult(BaseModel):
    """Immutable outcome of correlation graph construction, centrality scoring, and truncation metrics."""

    model_config = ConfigDict(frozen=True)

    centrality_score: float
    node_count: int
    edge_count: int
    top_entities: tuple[str, ...] = Field(default_factory=tuple)
    dot_representation: str
    input_event_count: int = 0
    processed_event_count: int = 0
    event_limit_reached: bool = False
    node_limit_reached: bool = False
    edge_limit_reached: bool = False
    is_truncated: bool = False


def build_correlation_graph(
    events: list[dict[str, Any]],
    max_nodes: int = 250,
    max_edges: int = 600,
) -> CorrelationGraphResult:
    """Constructs a bounded NetworkX graph and exports safe, sanitized DOT markup with explicit truncation telemetry."""
    input_count = len(events)
    if not events:
        return CorrelationGraphResult(
            centrality_score=0.0,
            node_count=0,
            edge_count=0,
            top_entities=(),
            dot_representation="strict graph ThreatGraph { node [shape=box]; }",
            input_event_count=0,
            processed_event_count=0,
            event_limit_reached=False,
            node_limit_reached=False,
            edge_limit_reached=False,
            is_truncated=False,
        )

    g: nx.Graph = nx.Graph()
    event_limit_reached = input_count > MAX_CORRELATION_EVENTS
    bounded_events = events[:MAX_CORRELATION_EVENTS]
    if event_limit_reached:
        logger.warning(
            "Correlation events bounded from %d to %d",
            input_count,
            MAX_CORRELATION_EVENTS,
        )

    node_limit_reached = False
    edge_limit_reached = False

    def _safe_add_edge(u: str, v: str, edge_type: str) -> bool:
        nonlocal node_limit_reached, edge_limit_reached
        if g.number_of_edges() >= max_edges:
            edge_limit_reached = True
            return False
        new_nodes = (0 if u in g else 1) + (0 if v in g else 1)
        if g.number_of_nodes() + new_nodes > max_nodes:
            node_limit_reached = True
            return False
        g.add_edge(u, v, type=edge_type)
        return True

    processed_events = 0
    for e in bounded_events:
        if not isinstance(e, dict):
            continue
        if g.number_of_nodes() >= max_nodes or g.number_of_edges() >= max_edges:
            logger.warning(
                "Correlation graph hit resource limits: nodes=%d, edges=%d",
                g.number_of_nodes(),
                g.number_of_edges(),
            )
            if g.number_of_nodes() >= max_nodes:
                node_limit_reached = True
            if g.number_of_edges() >= max_edges:
                edge_limit_reached = True
            break

        processed_events += 1
        src_ip = e.get("source_ip")
        user = e.get("user") or e.get("username")
        dest_port = parse_valid_port(e.get("destination_port"))

        if src_ip and user:
            u_node = _bound_entity("IP", src_ip)
            v_node = _bound_entity("User", user)
            if not _safe_add_edge(u_node, v_node, "login"):
                break
        if src_ip and dest_port is not None:
            u_node = _bound_entity("IP", src_ip)
            v_node = _bound_entity("Port", dest_port)
            if not _safe_add_edge(u_node, v_node, "probe"):
                break

    is_truncated = event_limit_reached or node_limit_reached or edge_limit_reached

    if g.number_of_nodes() == 0:
        return CorrelationGraphResult(
            centrality_score=0.0,
            node_count=0,
            edge_count=0,
            top_entities=(),
            dot_representation="strict graph ThreatGraph { node [shape=box]; }",
            input_event_count=input_count,
            processed_event_count=processed_events,
            event_limit_reached=event_limit_reached,
            node_limit_reached=node_limit_reached,
            edge_limit_reached=edge_limit_reached,
            is_truncated=is_truncated,
        )

    deg = nx.degree_centrality(g)
    try:
        bet = nx.betweenness_centrality(g)
    except Exception as exc:
        logger.warning(
            "Betweenness centrality calculation failed; defaulting to 0.0: %s",
            type(exc).__name__,
        )
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
        top_entities=tuple(top_nodes),
        dot_representation="\n".join(lines),
        input_event_count=input_count,
        processed_event_count=processed_events,
        event_limit_reached=event_limit_reached,
        node_limit_reached=node_limit_reached,
        edge_limit_reached=edge_limit_reached,
        is_truncated=is_truncated,
    )
