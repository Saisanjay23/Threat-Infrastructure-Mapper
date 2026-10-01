"""Graph, threat cluster and scoring-configuration endpoints."""

from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import client_ip, db_dep, require
from app.core.security import Permission
from app.db.mongo import Collections
from app.graph.builder import load_graph_for_cluster, load_graph_for_investigation, load_neighborhood, serialize_graph
from app.models.cluster import ClusterListItem, ClusterNote, ClusterOut, ClusterUpdate
from app.models.common import Message, Page, new_id, utcnow
from app.models.scoring import ScoringConfig, ScoringConfigOut
from app.models.user import CurrentUser
from app.repositories.base import paginate
from app.services.audit import audit
from app.services.clusters import ClusterEngine
from app.services.scoring_config import get_scoring, reset_scoring, save_scoring

router = APIRouter(tags=["Graph & Clusters"])


@router.get(
    "/graph/{graph_id}", summary="Investigation / cluster / asset relationship graph (NetworkX, React Flow format)"
)
async def get_graph(
    graph_id: str,
    kind: Literal["auto", "investigation", "cluster", "asset"] = "auto",
    depth: int = Query(1, ge=1, le=3, description="Neighbourhood depth when kind=asset"),
    max_nodes: int = Query(1500, ge=10, le=5000),
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)),
    db=Depends(db_dep),
) -> dict[str, Any]:
    if kind == "auto":
        if graph_id.startswith("inv_"):
            kind = "investigation"
        elif graph_id.startswith("TIM-CL-"):
            kind = "cluster"
        else:
            kind = "asset"
    focus = None
    if kind == "investigation":
        inv = await db[Collections.INVESTIGATIONS].find_one({"_id": graph_id}, {"root_asset_id": 1})
        if not inv:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
        g = await load_graph_for_investigation(db, graph_id, max_nodes)
        focus = inv.get("root_asset_id")
    elif kind == "cluster":
        if not await db[Collections.CLUSTERS].find_one({"_id": graph_id}, {"_id": 1}):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Cluster not found")
        g = await load_graph_for_cluster(db, graph_id, max_nodes)
    else:
        if not await db[Collections.ASSETS].find_one({"_id": graph_id}, {"_id": 1}):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
        g = await load_neighborhood(db, graph_id, depth, max_nodes)
        focus = graph_id
    payload = serialize_graph(g, focus=focus)
    payload.update({"id": graph_id, "kind": kind, "focus": focus})
    return payload


# ---------------------------------------------------------------------------- clusters
@router.get("/clusters", response_model=Page[ClusterListItem], summary="Threat clusters")
async def list_clusters(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    q: str | None = Query(None, max_length=200),
    min_confidence: int | None = Query(None, ge=0, le=100),
    severity: str | None = None,
    investigation_id: str | None = None,
    sort: Literal["updated_at", "confidence", "created_at"] = "updated_at",
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)),
    db=Depends(db_dep),
) -> Page[ClusterListItem]:
    query: dict[str, Any] = {}
    if q:
        rx = {"$regex": re.escape(q.strip()), "$options": "i"}
        query["$or"] = [{"name": rx}, {"domains": rx}, {"_id": rx}, {"tracking_ids": rx}, {"ips": rx}]
    if min_confidence is not None:
        query["confidence"] = {"$gte": min_confidence}
    if severity:
        query["severity"] = severity
    if investigation_id:
        query["investigation_ids"] = investigation_id
    skip, limit = paginate(page, page_size)
    col = db[Collections.CLUSTERS]
    docs = (
        await col.find(query, {"asset_ids": 0, "fingerprint_ids": 0})
        .sort(sort, -1)
        .skip(skip)
        .limit(limit)
        .to_list(length=limit)
    )
    total = await col.count_documents(query)
    for d in docs:
        d["domains"] = d.get("domains", [])[:10]
        d["screenshots"] = d.get("screenshots", [])[:4]
    return Page(items=[ClusterListItem.model_validate(d) for d in docs], total=total, page=page, page_size=limit)


@router.get("/clusters/{cluster_id}", response_model=ClusterOut, summary="Cluster detail")
async def get_cluster(
    cluster_id: str, _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)), db=Depends(db_dep)
) -> ClusterOut:
    doc = await db[Collections.CLUSTERS].find_one({"_id": cluster_id})
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cluster not found")
    return ClusterOut.model_validate(doc)


@router.patch("/clusters/{cluster_id}", response_model=ClusterOut, summary="Rename, tag or re-rate a cluster")
async def update_cluster(
    cluster_id: str,
    body: ClusterUpdate,
    request: Request,
    user: CurrentUser = Depends(require(Permission.CASE_WRITE)),
    db=Depends(db_dep),
) -> ClusterOut:
    fields = body.model_dump(exclude_none=True)
    if "tags" in fields:
        fields["tags"] = sorted({t.strip().lower() for t in fields["tags"] if t.strip()})
    fields["updated_at"] = utcnow()
    doc = await db[Collections.CLUSTERS].find_one_and_update(
        {"_id": cluster_id}, {"$set": fields}, return_document=True
    )
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cluster not found")
    await audit(
        "cluster.update",
        username=user.username,
        role=user.role,
        resource_type="cluster",
        resource_id=cluster_id,
        ip=client_ip(request),
        details={k: v for k, v in fields.items() if k != "updated_at"},
    )
    return ClusterOut.model_validate(doc)


@router.post("/clusters/{cluster_id}/notes", response_model=ClusterOut, summary="Add an analyst note to a cluster")
async def add_cluster_note(
    cluster_id: str, body: ClusterNote, user: CurrentUser = Depends(require(Permission.CASE_WRITE)), db=Depends(db_dep)
) -> ClusterOut:
    note = {"id": new_id("note_"), "text": body.text, "author": user.username, "created_at": utcnow()}
    doc = await db[Collections.CLUSTERS].find_one_and_update(
        {"_id": cluster_id}, {"$push": {"notes": note}, "$set": {"updated_at": utcnow()}}, return_document=True
    )
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cluster not found")
    return ClusterOut.model_validate(doc)


@router.post("/clusters/rebuild", summary="Re-cluster the entire inventory over distinctive shared fingerprints")
async def rebuild_clusters(
    request: Request, user: CurrentUser = Depends(require(Permission.SETTINGS_ADMIN)), db=Depends(db_dep)
) -> dict[str, Any]:
    config = await get_scoring(db)
    ids = await ClusterEngine(db).rebuild_all(config)
    await audit(
        "cluster.rebuild", username=user.username, role=user.role, ip=client_ip(request), details={"clusters": len(ids)}
    )
    return {"clusters": ids, "count": len(ids)}


# ---------------------------------------------------------------------------- scoring
@router.get("/settings/scoring", response_model=ScoringConfigOut, summary="Correlation scoring weights and thresholds")
async def scoring(
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)), db=Depends(db_dep)
) -> ScoringConfigOut:
    return ScoringConfigOut(**(await get_scoring(db)).model_dump())


@router.put("/settings/scoring", response_model=ScoringConfigOut, summary="Update scoring weights and thresholds")
async def update_scoring(
    body: ScoringConfig,
    request: Request,
    user: CurrentUser = Depends(require(Permission.SETTINGS_ADMIN)),
    db=Depends(db_dep),
) -> ScoringConfigOut:
    saved = await save_scoring(db, body, user.username)
    await audit(
        "settings.scoring.update",
        username=user.username,
        role=user.role,
        ip=client_ip(request),
        details={"weights": saved.weights, "thresholds": saved.thresholds.model_dump()},
    )
    return ScoringConfigOut(**saved.model_dump())


@router.delete("/settings/scoring", response_model=Message, summary="Restore default scoring")
async def delete_scoring(
    request: Request, user: CurrentUser = Depends(require(Permission.SETTINGS_ADMIN)), db=Depends(db_dep)
) -> Message:
    await reset_scoring(db)
    await audit("settings.scoring.reset", username=user.username, role=user.role, ip=client_ip(request))
    return Message(message="Scoring restored to defaults")
