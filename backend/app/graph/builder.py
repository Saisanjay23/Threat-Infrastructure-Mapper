"""NetworkX graph model built from assets + relationships, with layout and analytics for the UI."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

import networkx as nx
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.mongo import Collections

FINGERPRINT_TYPES = {
    "certificate",
    "favicon",
    "analytics",
    "pixel",
    "tracking",
    "logo",
    "asn",
    "hosting",
    "nameserver",
    "ip",
}
HOST_TYPES = {"domain", "url", "ip"}
NODE_PROJECTION = {
    "type": 1,
    "value": 1,
    "status": 1,
    "confidence": 1,
    "confidence_level": 1,
    "impersonation_score": 1,
    "cluster_ids": 1,
    "is_root": 1,
    "tags": 1,
    "attributes.title": 1,
    "attributes.web.title": 1,
    "attributes.screenshots.thumbnail": 1,
    "attributes.family": 1,
    "attributes.file_id": 1,
    "sources": 1,
}


def build_graph(assets: list[dict[str, Any]], edges: list[dict[str, Any]]) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for a in assets:
        g.add_node(a["_id"], **{k: v for k, v in a.items() if k != "_id"})
    for e in edges:
        if e["source"] in g and e["target"] in g:
            g.add_edge(
                e["source"],
                e["target"],
                key=e["_id"],
                type=e["type"],
                weight=float(e.get("weight") or 1.0),
                sources=e.get("sources", []),
                evidence=e.get("evidence", [])[-3:],
            )
    return g


async def load_graph_for_investigation(db: AsyncIOMotorDatabase, inv_id: str, max_nodes: int = 2500) -> nx.MultiDiGraph:
    assets = (
        await db[Collections.ASSETS]
        .find({"investigation_ids": inv_id}, NODE_PROJECTION)
        .limit(max_nodes)
        .to_list(length=max_nodes)
    )
    ids = [a["_id"] for a in assets]
    edges = (
        await db[Collections.RELATIONSHIPS]
        .find({"source": {"$in": ids}, "target": {"$in": ids}})
        .to_list(length=max_nodes * 6)
    )
    return build_graph(assets, edges)


async def load_graph_for_cluster(db: AsyncIOMotorDatabase, cluster_id: str, max_nodes: int = 2500) -> nx.MultiDiGraph:
    cluster = await db[Collections.CLUSTERS].find_one({"_id": cluster_id}, {"asset_ids": 1, "fingerprint_ids": 1})
    if not cluster:
        return nx.MultiDiGraph()
    ids = list({*cluster.get("asset_ids", []), *cluster.get("fingerprint_ids", [])})[:max_nodes]
    assets = await db[Collections.ASSETS].find({"_id": {"$in": ids}}, NODE_PROJECTION).to_list(length=max_nodes)
    edges = (
        await db[Collections.RELATIONSHIPS]
        .find({"source": {"$in": ids}, "target": {"$in": ids}})
        .to_list(length=max_nodes * 6)
    )
    return build_graph(assets, edges)


async def load_neighborhood(
    db: AsyncIOMotorDatabase, asset_id: str, depth: int = 1, max_nodes: int = 600
) -> nx.MultiDiGraph:
    frontier = {asset_id}
    seen = {asset_id}
    all_edges: dict[str, dict[str, Any]] = {}
    for _ in range(max(1, min(depth, 3))):
        if not frontier or len(seen) >= max_nodes:
            break
        edges = (
            await db[Collections.RELATIONSHIPS]
            .find({"$or": [{"source": {"$in": list(frontier)}}, {"target": {"$in": list(frontier)}}]})
            .limit(max_nodes * 4)
            .to_list(length=max_nodes * 4)
        )
        nxt: set[str] = set()
        for e in edges:
            all_edges[e["_id"]] = e
            for n in (e["source"], e["target"]):
                if n not in seen and len(seen) < max_nodes:
                    seen.add(n)
                    nxt.add(n)
        frontier = nxt
    assets = await db[Collections.ASSETS].find({"_id": {"$in": list(seen)}}, NODE_PROJECTION).to_list(length=max_nodes)
    return build_graph(assets, list(all_edges.values()))


def _layout(g: nx.MultiDiGraph) -> dict[str, tuple[float, float]]:
    n = g.number_of_nodes()
    if n == 0:
        return {}
    simple = nx.Graph(g)
    scale = 220 * math.sqrt(n) + 300
    if n == 1:
        return {next(iter(g.nodes)): (0.0, 0.0)}
    if n <= 400:
        pos = nx.spring_layout(simple, k=2.2 / math.sqrt(n), iterations=120, seed=42, scale=scale)
    else:
        pos = nx.spring_layout(simple, k=1.5 / math.sqrt(n), iterations=50, seed=42, scale=scale)
    return {node: (float(x), float(y)) for node, (x, y) in pos.items()}


def serialize_graph(g: nx.MultiDiGraph, *, focus: str | None = None) -> dict[str, Any]:
    """Convert to a React-Flow friendly payload with positions, centrality and statistics."""
    positions = _layout(g)
    undirected = nx.Graph(g)
    degree = dict(g.degree())
    centrality: dict[str, float] = {}
    if 0 < undirected.number_of_nodes() <= 1500:
        centrality = nx.degree_centrality(undirected)
    components = list(nx.connected_components(undirected)) if undirected.number_of_nodes() else []
    component_of = {node: idx for idx, comp in enumerate(sorted(components, key=len, reverse=True)) for node in comp}

    nodes = []
    for node_id, data in g.nodes(data=True):
        attrs = data.get("attributes") or {}
        label = data.get("value", node_id)
        if data.get("type") == "url" and len(label) > 60:
            label = label[:57] + "..."
        x, y = positions.get(node_id, (0.0, 0.0))
        nodes.append(
            {
                "id": node_id,
                "type": data.get("type"),
                "label": label,
                "value": data.get("value"),
                "position": {"x": round(x, 1), "y": round(y, 1)},
                "data": {
                    "status": data.get("status"),
                    "confidence": data.get("confidence"),
                    "confidence_level": data.get("confidence_level"),
                    "impersonation_score": data.get("impersonation_score"),
                    "cluster_ids": data.get("cluster_ids", []),
                    "is_root": bool(data.get("is_root")) or node_id == focus,
                    "title": attrs.get("title") or (attrs.get("web") or {}).get("title"),
                    "thumbnail": (attrs.get("screenshots") or {}).get("thumbnail"),
                    "family": attrs.get("family"),
                    "file_id": attrs.get("file_id"),
                    "degree": degree.get(node_id, 0),
                    "centrality": round(centrality.get(node_id, 0.0), 4),
                    "component": component_of.get(node_id, 0),
                    "tags": data.get("tags", []),
                },
            }
        )
    edges = []
    for source, target, key, data in g.edges(keys=True, data=True):
        edges.append(
            {
                "id": key,
                "source": source,
                "target": target,
                "type": data.get("type"),
                "weight": data.get("weight", 1.0),
                "sources": data.get("sources", []),
                "evidence": data.get("evidence", []),
            }
        )
    type_counts = Counter(d.get("type") for _, d in g.nodes(data=True))
    rel_counts = Counter(d.get("type") for *_, d in g.edges(data=True))
    hubs = sorted(((n, degree.get(n, 0)) for n in g.nodes), key=lambda t: t[1], reverse=True)[:10]
    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": g.number_of_nodes(),
            "edges": g.number_of_edges(),
            "components": len(components),
            "node_types": dict(type_counts),
            "relationship_types": dict(rel_counts),
            "density": round(nx.density(undirected), 5) if undirected.number_of_nodes() > 1 else 0.0,
            "hubs": [
                {"id": n, "label": g.nodes[n].get("value"), "type": g.nodes[n].get("type"), "degree": d}
                for n, d in hubs
            ],
        },
    }


def shared_neighbors(g: nx.MultiDiGraph, a: str, b: str) -> list[tuple[str, set[str], set[str]]]:
    """Fingerprint nodes adjacent to both a and b, with the relation types used on each side."""

    def neigh(n: str) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for _, t, d in g.out_edges(n, data=True):
            out.setdefault(t, set()).add(d.get("type"))
        for s, _, d in g.in_edges(n, data=True):
            out.setdefault(s, set()).add(d.get("type"))
        return out

    na, nb = neigh(a), neigh(b)
    return [(n, na[n], nb[n]) for n in set(na) & set(nb)]
