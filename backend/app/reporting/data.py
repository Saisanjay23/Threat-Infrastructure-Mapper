"""Assemble a report data model for an investigation, cluster, case or ad-hoc asset selection."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.db.mongo import Collections
from app.graph.builder import build_graph, serialize_graph
from app.models.case import ExportRequest
from app.models.common import utcnow
from app.repositories.artifacts import ArtifactRepository
from app.services.scoring_config import get_scoring

HOST_TYPES = ("domain", "ip", "url")
ASSET_PROJECTION = {"enrichment": 0}


class ReportScopeError(LookupError):
    pass


@dataclass
class Screenshot:
    asset_id: str
    value: str
    kind: str
    content: bytes
    content_type: str


@dataclass
class ReportData:
    title: str
    scope_type: str
    scope_id: str | None
    generated_at: datetime
    generated_by: str
    tlp: str
    sections: list[str]
    executive_summary: list[str] = field(default_factory=list)
    investigations: list[dict[str, Any]] = field(default_factory=list)
    root: dict[str, Any] | None = None
    assets: list[dict[str, Any]] = field(default_factory=list)
    fingerprints: list[dict[str, Any]] = field(default_factory=list)
    clusters: list[dict[str, Any]] = field(default_factory=list)
    case: dict[str, Any] | None = None
    screenshots: list[Screenshot] = field(default_factory=list)
    graph: dict[str, Any] | None = None
    notes: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    scoring: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "scope": {"type": self.scope_type, "id": self.scope_id},
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "tlp": self.tlp,
            "executive_summary": self.executive_summary,
            "statistics": self.stats,
            "investigations": self.investigations,
            "root_asset": self.root,
            "assets": self.assets,
            "fingerprints": self.fingerprints,
            "clusters": self.clusters,
            "case": self.case,
            "graph": {"stats": (self.graph or {}).get("stats"), "edges": (self.graph or {}).get("edges", [])[:5000]},
            "notes": self.notes,
            "scoring_model": self.scoring,
        }


def _clean(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    out["id"] = out.pop("_id")
    return out


def asset_row(a: dict[str, Any], inv_id: str | None) -> dict[str, Any]:
    attrs = a.get("attributes") or {}
    fp = a.get("fingerprints") or {}
    corr = (a.get("correlation") or {}).get(inv_id or "") if inv_id else None
    if corr is None and a.get("correlation"):
        corr = max(a["correlation"].values(), key=lambda c: c.get("score", 0))
    web = attrs.get("web") or {}
    infra = attrs.get("infrastructure") or {}
    return {
        "id": a["_id"],
        "type": a["type"],
        "value": a["value"],
        "status": a.get("status"),
        "confidence": a.get("confidence"),
        "confidence_level": a.get("confidence_level"),
        "impersonation_score": a.get("impersonation_score"),
        "brand_similarity_score": a.get("brand_similarity_score"),
        "title": attrs.get("title") or web.get("title"),
        "final_url": web.get("final_url"),
        "http_status": web.get("status_code"),
        "ips": infra.get("ips") or fp.get("ips") or ([a["value"]] if a["type"] == "ip" else []),
        "asn": fp.get("asn") or (infra.get("asns") or [None])[0],
        "hosting": fp.get("hosting")
        if isinstance(fp.get("hosting"), str)
        else (infra.get("hosting_providers") or [None])[0],
        "registrar": infra.get("registrar"),
        "created": infra.get("created"),
        "nameservers": infra.get("nameservers") or fp.get("nameservers") or [],
        "tracking_ids": fp.get("tracking_ids") or [],
        "favicon_mmh3": fp.get("favicon_mmh3"),
        "cert_sha256": fp.get("cert_sha256"),
        "content_reasons": (attrs.get("content") or {}).get("reasons", []),
        "brand_indicators": (attrs.get("brand") or {}).get("indicators", []),
        "correlation_score": (corr or {}).get("score"),
        "correlation_matches": [
            {
                "feature": m.get("feature"),
                "label": m.get("label"),
                "weight": m.get("weight"),
                "values": m.get("values", []),
            }
            for m in (corr or {}).get("matches", [])
        ],
        "cluster_ids": a.get("cluster_ids", []),
        "sources": a.get("sources", []),
        "tags": a.get("tags", []),
        "first_seen": a.get("first_seen"),
        "last_seen": a.get("last_seen"),
        "screenshots": attrs.get("screenshots") or {},
    }


async def build_report_data(
    db: AsyncIOMotorDatabase, fs: AsyncIOMotorGridFSBucket, req: ExportRequest, username: str
) -> ReportData:
    now = utcnow()
    investigations: list[dict[str, Any]] = []
    clusters: list[dict[str, Any]] = []
    case: dict[str, Any] | None = None
    asset_query: dict[str, Any]
    inv_id: str | None = None
    notes: list[dict[str, Any]] = []

    if req.investigation_id:
        inv = await db[Collections.INVESTIGATIONS].find_one({"_id": req.investigation_id})
        if not inv:
            raise ReportScopeError("Investigation not found")
        inv_id = inv["_id"]
        investigations = [inv]
        asset_query = {"investigation_ids": inv_id}
        clusters = await db[Collections.CLUSTERS].find({"investigation_ids": inv_id}).to_list(length=50)
        scope_type, scope_id = "investigation", inv_id
        title = req.title or f"Infrastructure investigation: {inv['normalized']}"
    elif req.cluster_id:
        cl = await db[Collections.CLUSTERS].find_one({"_id": req.cluster_id})
        if not cl:
            raise ReportScopeError("Cluster not found")
        clusters = [cl]
        asset_query = {"_id": {"$in": cl.get("asset_ids", []) + cl.get("fingerprint_ids", [])}}
        investigations = (
            await db[Collections.INVESTIGATIONS]
            .find({"_id": {"$in": cl.get("investigation_ids", [])}})
            .to_list(length=100)
        )
        scope_type, scope_id = "cluster", cl["_id"]
        title = req.title or f"Threat cluster report: {cl['name']}"
        notes.extend({"source": f"cluster {cl['_id']}", **n} for n in cl.get("notes", []))
    elif req.case_id:
        case = await db[Collections.CASES].find_one({"_id": req.case_id})
        if not case:
            raise ReportScopeError("Case not found")
        investigations = (
            await db[Collections.INVESTIGATIONS]
            .find({"_id": {"$in": case.get("investigation_ids", [])}})
            .to_list(length=200)
        )
        clusters = (
            await db[Collections.CLUSTERS].find({"_id": {"$in": case.get("cluster_ids", [])}}).to_list(length=100)
        )
        ids = set(case.get("asset_ids", []))
        for cl in clusters:
            ids |= set(cl.get("asset_ids", []))
        or_clauses: list[dict[str, Any]] = [{"_id": {"$in": list(ids)}}]
        if investigations:
            or_clauses.append({"investigation_ids": {"$in": [i["_id"] for i in investigations]}})
        asset_query = {"$or": or_clauses}
        scope_type, scope_id = "case", case["_id"]
        title = req.title or f"Case {case['_id']}: {case['title']}"
        notes.extend({"source": f"case {case['_id']}", **n} for n in case.get("notes", []))
    else:
        asset_query = {"_id": {"$in": req.asset_ids or []}}
        scope_type, scope_id = "selection", None
        title = req.title or f"Selected assets ({len(req.asset_ids or [])})"

    if len(investigations) == 1 and not inv_id:
        inv_id = investigations[0]["_id"]
    for inv in investigations:
        notes.extend({"source": f"investigation {inv['_id']}", **n} for n in inv.get("notes", []))
    if req.analyst_notes:
        notes.append({"source": "report", "author": username, "created_at": now, "text": req.analyst_notes})

    docs = await db[Collections.ASSETS].find(asset_query, ASSET_PROJECTION).to_list(length=req.max_assets * 4)
    hosts = [d for d in docs if d["type"] in HOST_TYPES and (d.get("confidence") or 0) >= req.min_confidence]
    hosts.sort(
        key=lambda d: (d.get("is_root") is True, d.get("confidence") or 0, d.get("impersonation_score") or 0),
        reverse=True,
    )
    hosts = hosts[: req.max_assets]
    prints = [d for d in docs if d["type"] not in HOST_TYPES and d["type"] != "cluster"]

    root = None
    if investigations and investigations[0].get("root_asset_id"):
        root_doc = await db[Collections.ASSETS].find_one({"_id": investigations[0]["root_asset_id"]}, ASSET_PROJECTION)
        if root_doc and root_doc["type"] == "url":
            host = next(
                (d for d in docs if d["type"] in ("domain", "ip") and (d.get("attributes") or {}).get("web")), None
            )
            root_doc = host or root_doc
        root = asset_row(root_doc, inv_id) if root_doc else None

    screenshots: list[Screenshot] = []
    if "screenshots" in req.sections and req.max_screenshots:
        artifacts = ArtifactRepository(db, fs)
        for d in hosts:
            shots = (d.get("attributes") or {}).get("screenshots") or {}
            file_id = shots.get("desktop") or shots.get("thumbnail")
            if not file_id:
                continue
            found = await artifacts.read_file(file_id)
            if found:
                content, meta = found
                screenshots.append(
                    Screenshot(
                        d["_id"],
                        d["value"],
                        "desktop" if shots.get("desktop") else "thumbnail",
                        content,
                        str(meta.get("content_type") or "image/png"),
                    )
                )
            if len(screenshots) >= req.max_screenshots:
                break

    graph = None
    if "graph_snapshot" in req.sections:
        graph_ids = [d["_id"] for d in hosts[:150]] + [p["_id"] for p in prints[:250]]
        edges = (
            await db[Collections.RELATIONSHIPS]
            .find({"source": {"$in": graph_ids}, "target": {"$in": graph_ids}})
            .to_list(length=4000)
        )
        node_docs = [d for d in hosts[:150]] + prints[:250]
        graph = serialize_graph(build_graph(node_docs, edges), focus=(root or {}).get("id"))

    rows = [asset_row(d, inv_id) for d in hosts]
    by_type = Counter(d["type"] for d in docs)
    status = Counter(d.get("status") or "UNKNOWN" for d in docs if d["type"] in ("domain", "ip"))
    config = await get_scoring(db)
    levels = Counter(config.thresholds.level(r["confidence"]).value for r in rows if r["confidence"] is not None)
    stats = {
        "assets": len(docs),
        "by_type": dict(by_type),
        "site_status": dict(status),
        "confidence_levels": dict(levels),
        "relationships": (graph or {}).get("stats", {}).get("edges"),
        "clusters": len(clusters),
        "investigations": len(investigations),
        "high_confidence": sum(1 for r in rows if (r["confidence"] or 0) >= config.thresholds.high),
        "max_impersonation": max((r["impersonation_score"] or 0 for r in rows), default=0),
    }
    data = ReportData(
        title=title,
        scope_type=scope_type,
        scope_id=scope_id,
        generated_at=now,
        generated_by=username,
        tlp=req.tlp,
        sections=list(req.sections),
        investigations=[_clean({k: v for k, v in i.items() if k != "provider_runs"}) for i in investigations],
        root=root,
        assets=rows,
        fingerprints=[
            {
                "id": p["_id"],
                "type": p["type"],
                "value": p["value"],
                "family": (p.get("attributes") or {}).get("family"),
            }
            for p in prints[:1000]
        ],
        clusters=[_clean(c) for c in clusters],
        case=_clean(case) if case else None,
        screenshots=screenshots,
        graph=graph,
        notes=notes,
        stats=stats,
        scoring=config.model_dump(),
    )
    data.executive_summary = executive_summary(data)
    return data


def executive_summary(d: ReportData) -> list[str]:
    s = d.stats
    lines: list[str] = []
    bt = s.get("by_type", {})
    if d.scope_type == "investigation" and d.investigations:
        inv = d.investigations[0]
        lines.append(
            f"TIM investigated the {inv['ioc_type']} indicator {inv['normalized']} on "
            f"{inv['created_at']:%Y-%m-%d %H:%M} UTC (requested by {inv['created_by']})."
        )
    elif d.scope_type == "cluster" and d.clusters:
        c = d.clusters[0]
        lines.append(
            f"Threat cluster {c['id']} ('{c['name']}') groups {len(c.get('asset_ids', []))} hosts that share "
            f"distinctive infrastructure fingerprints; cluster confidence {c.get('confidence')} "
            f"({c.get('confidence_level')}), severity {str(c.get('severity')).upper()}."
        )
    elif d.scope_type == "case" and d.case:
        lines.append(
            f"Case {d.case['id']} '{d.case['title']}' (severity {d.case['severity']}, status "
            f"{d.case['status']}) covers {len(d.investigations)} investigation(s) and {len(d.clusters)} cluster(s)."
        )
    if d.root:
        r = d.root
        status_line = f"The primary site {r['value']} is {r.get('status') or 'UNKNOWN'}"
        if r.get("content_reasons"):
            status_line += f" ({r['content_reasons'][0]})"
        lines.append(status_line + ".")
        if r.get("impersonation_score"):
            lines.append(
                f"Brand impersonation confidence is {r['impersonation_score']}/100"
                + (f": {'; '.join(r['brand_indicators'][:3])}." if r.get("brand_indicators") else ".")
            )
    lines.append(
        f"{s.get('assets', 0)} related assets were identified: {bt.get('domain', 0)} domains, {bt.get('ip', 0)} IP "
        f"addresses, {bt.get('certificate', 0)} certificates, "
        f"{bt.get('analytics', 0) + bt.get('pixel', 0) + bt.get('tracking', 0)} analytics/tracking IDs and "
        f"{bt.get('favicon', 0)} favicons."
    )
    levels = s.get("confidence_levels", {})
    strong = levels.get("Very High", 0) + levels.get("High", 0)
    if strong:
        lines.append(f"{strong} asset(s) are attributed to the same operation with High or Very High confidence.")
    if d.clusters and d.scope_type != "cluster":
        names = ", ".join(f"{c['id']} ({c.get('confidence_level')})" for c in d.clusters[:5])
        lines.append(f"Correlated infrastructure was grouped into {len(d.clusters)} threat cluster(s): {names}.")
    active = s.get("site_status", {}).get("ACTIVE", 0)
    if active:
        lines.append(f"{active} host(s) were ACTIVE at collection time and may warrant takedown or blocking.")
    return lines
