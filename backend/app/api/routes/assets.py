"""Asset inventory, asset detail and GridFS file streaming."""

from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from app.api.deps import db_dep, get_current_user_or_query, require
from app.core.security import Permission
from app.db.mongo import get_fs
from app.models.asset import ArtifactOut, AssetListItem, AssetOut, AssetTagUpdate
from app.models.common import AssetType, Page, SiteStatus
from app.models.user import CurrentUser
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.repositories.base import paginate
from app.repositories.relationships import RelationshipRepository

router = APIRouter(tags=["Assets"])

SORT_FIELDS = {"last_seen", "first_seen", "value", "type", "confidence", "impersonation_score", "status"}
INLINE_TYPES = ("image/", "text/plain", "application/json")


@router.get("/assets", response_model=Page[AssetListItem], summary="Search the asset inventory")
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    q: str | None = Query(None, max_length=256, description="Substring match on value"),
    asset_type: list[AssetType] | None = Query(None, alias="type"),
    site_status: list[SiteStatus] | None = Query(None, alias="status"),
    min_confidence: int | None = Query(None, ge=0, le=100),
    cluster_id: str | None = None,
    investigation_id: str | None = None,
    case_id: str | None = Query(None, description="Only assets attached to this case"),
    tag: str | None = None,
    source: str | None = None,
    sort: str = Query("last_seen"),
    order: Literal["asc", "desc"] = "desc",
    _: CurrentUser = Depends(require(Permission.ASSET_READ)),
    db=Depends(db_dep),
) -> Page[AssetListItem]:
    query: dict[str, Any] = {}
    if q:
        query["value"] = {"$regex": re.escape(q.strip().lower()), "$options": "i"}
    if asset_type:
        query["type"] = {"$in": [t.value for t in asset_type]}
    if site_status:
        query["status"] = {"$in": [s.value for s in site_status]}
    if min_confidence is not None:
        query["confidence"] = {"$gte": min_confidence}
    if cluster_id:
        query["cluster_ids"] = cluster_id
    if investigation_id:
        query["investigation_ids"] = investigation_id
    if case_id:
        case = await db["cases"].find_one({"_id": case_id}, {"asset_ids": 1})
        query["_id"] = {"$in": (case or {}).get("asset_ids", [])}
    if tag:
        query["tags"] = tag.lower()
    if source:
        query["sources"] = source
    if sort not in SORT_FIELDS:
        raise HTTPException(422, f"sort must be one of {sorted(SORT_FIELDS)}")
    skip, limit = paginate(page, page_size)
    items, total = await AssetRepository(db).find_page(
        query,
        sort=[(sort, 1 if order == "asc" else -1), ("_id", 1)],
        skip=skip,
        limit=limit,
        projection={"enrichment": 0, "correlation": 0},
    )
    return Page(items=[AssetListItem.model_validate(i) for i in items], total=total, page=page, page_size=limit)


@router.get("/asset/{asset_id}", summary="Asset detail with relationships and artifacts")
async def get_asset(
    asset_id: str, _: CurrentUser = Depends(require(Permission.ASSET_READ)), db=Depends(db_dep)
) -> dict[str, Any]:
    repo = AssetRepository(db)
    doc = await repo.get(asset_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    edges = await RelationshipRepository(db).for_assets([asset_id], limit=1000)
    neighbour_ids = list({e["target"] if e["source"] == asset_id else e["source"] for e in edges})
    neighbours = {
        n["_id"]: n
        for n in await db["assets"]
        .find({"_id": {"$in": neighbour_ids}}, {"type": 1, "value": 1, "status": 1, "confidence": 1})
        .to_list(length=1000)
    }
    relationships = []
    for e in edges:
        other_id = e["target"] if e["source"] == asset_id else e["source"]
        other = neighbours.get(other_id)
        if other is None:
            continue
        relationships.append(
            {
                "id": e["_id"],
                "type": e["type"],
                "direction": "out" if e["source"] == asset_id else "in",
                "other": {
                    "id": other_id,
                    "type": other["type"],
                    "value": other["value"],
                    "status": other.get("status"),
                    "confidence": other.get("confidence"),
                },
                "sources": e.get("sources", []),
                "evidence": e.get("evidence", [])[-5:],
                "first_seen": e.get("first_seen"),
                "last_seen": e.get("last_seen"),
            }
        )
    artifacts = await ArtifactRepository(db, get_fs()).for_asset(asset_id)
    return {
        "asset": AssetOut.model_validate(doc).model_dump(mode="json"),
        "relationships": relationships,
        "artifacts": [
            ArtifactOut.model_validate(
                {**a, "data": None if str(a["kind"]).startswith("provider:") else a.get("data")}
            ).model_dump(mode="json")
            for a in artifacts
        ],
    }


@router.put("/asset/{asset_id}/tags", response_model=AssetOut, summary="Replace an asset's tags")
async def set_tags(
    asset_id: str, body: AssetTagUpdate, _: CurrentUser = Depends(require(Permission.CASE_WRITE)), db=Depends(db_dep)
) -> AssetOut:
    tags = sorted({t.strip().lower() for t in body.tags if t.strip()})
    doc = await AssetRepository(db).update(asset_id, {"tags": tags}, touch=False)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return AssetOut.model_validate(doc)


@router.get(
    "/files/{file_id}",
    summary="Download a stored GridFS file (screenshot, HTML, favicon, upload)",
    response_class=Response,
)
async def get_file(
    file_id: str, download: bool = False, _: CurrentUser = Depends(get_current_user_or_query), db=Depends(db_dep)
) -> Response:
    found = await ArtifactRepository(db, get_fs()).read_file(file_id)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    content, meta = found
    content_type = str(meta.get("content_type") or "application/octet-stream")
    # Never render collected (hostile) HTML/SVG inline in the analyst's browser origin.
    safe_inline = content_type.startswith(INLINE_TYPES) and "svg" not in content_type
    headers = {
        "Cache-Control": "private, max-age=3600",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox",
    }
    if download or not safe_inline:
        headers["Content-Disposition"] = f'attachment; filename="{file_id}"'
        if not safe_inline:
            content_type = (
                "application/octet-stream" if "html" in content_type or "svg" in content_type else content_type
            )
    return Response(content=content, media_type=content_type, headers=headers)
