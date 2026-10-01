"""Investigation endpoints."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import client_ip, db_dep, require, runner_dep
from app.core.security import Permission
from app.db.mongo import get_fs
from app.models.asset import ArtifactOut, AssetListItem
from app.models.common import Message, Page, new_id, utcnow
from app.models.investigation import (
    BulkInvestigationCreate,
    BulkInvestigationOut,
    InvestigationCreate,
    InvestigationListItem,
    InvestigationNote,
    InvestigationOut,
    InvestigationStatus,
)
from app.models.user import CurrentUser
from app.pipeline.runner import PipelineRunner
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.repositories.base import paginate
from app.repositories.investigations import InvestigationRepository
from app.services.audit import audit
from app.utils.ioc import InvalidIOCError

router = APIRouter(tags=["Investigations"])


@router.post(
    "/investigate",
    response_model=InvestigationOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start an investigation from a single IOC (domain, URL, IP or certificate hash)",
)
async def investigate(
    body: InvestigationCreate,
    request: Request,
    user: CurrentUser = Depends(require(Permission.INVESTIGATION_WRITE)),
    runner: PipelineRunner = Depends(runner_dep),
) -> InvestigationOut:
    try:
        doc = runner.new_document(
            body.ioc, body.options, created_by=user.username, tags=body.tags, case_id=body.case_id
        )
    except InvalidIOCError as exc:
        raise HTTPException(422, str(exc)) from exc
    await runner.submit(doc)
    await audit(
        "investigation.create",
        username=user.username,
        role=user.role,
        resource_type="investigation",
        resource_id=doc["_id"],
        ip=client_ip(request),
        details={"ioc": doc["normalized"]},
    )
    return InvestigationOut.model_validate(doc)


@router.post(
    "/bulk-investigate",
    response_model=BulkInvestigationOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start investigations for up to 500 IOCs",
)
async def bulk_investigate(
    body: BulkInvestigationCreate,
    request: Request,
    user: CurrentUser = Depends(require(Permission.INVESTIGATION_WRITE)),
    runner: PipelineRunner = Depends(runner_dep),
) -> BulkInvestigationOut:
    bulk_id = new_id("blk_")
    ids: list[str] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in body.iocs:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            doc = runner.new_document(
                raw, body.options, created_by=user.username, tags=body.tags, case_id=body.case_id, bulk_id=bulk_id
            )
        except InvalidIOCError as exc:
            rejected.append({"ioc": raw, "reason": str(exc)})
            continue
        if doc["normalized"] in seen:
            rejected.append({"ioc": raw, "reason": "duplicate"})
            continue
        seen.add(doc["normalized"])
        await runner.submit(doc)
        ids.append(doc["_id"])
    await audit(
        "investigation.bulk_create",
        username=user.username,
        role=user.role,
        resource_type="bulk",
        resource_id=bulk_id,
        ip=client_ip(request),
        details={"accepted": len(ids), "rejected": len(rejected)},
    )
    return BulkInvestigationOut(bulk_id=bulk_id, investigation_ids=ids, rejected=rejected)


@router.get("/investigations", response_model=Page[InvestigationListItem], summary="List investigations")
async def list_investigations(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    q: str | None = Query(None, max_length=200, description="Substring match on IOC"),
    status_filter: InvestigationStatus | None = Query(None, alias="status"),
    tag: str | None = None,
    bulk_id: str | None = None,
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)),
    db=Depends(db_dep),
) -> Page[InvestigationListItem]:
    query: dict[str, Any] = {}
    if q:
        query["normalized"] = {"$regex": re.escape(q.strip().lower())}
    if status_filter:
        query["status"] = status_filter.value
    if tag:
        query["tags"] = tag.lower()
    if bulk_id:
        query["bulk_id"] = bulk_id
    skip, limit = paginate(page, page_size)
    items, total = await InvestigationRepository(db).find_page(
        query,
        sort=[("created_at", -1)],
        skip=skip,
        limit=limit,
        projection={"stages": 0, "provider_runs": 0, "notes": 0},
    )
    return Page(items=[InvestigationListItem.model_validate(i) for i in items], total=total, page=page, page_size=limit)


async def _get_or_404(db: Any, inv_id: str) -> dict[str, Any]:
    doc = await InvestigationRepository(db).get(inv_id, {"provider_runs": 0})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return doc


@router.get(
    "/investigation/{inv_id}", response_model=InvestigationOut, summary="Investigation detail and stage progress"
)
async def get_investigation(
    inv_id: str, _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)), db=Depends(db_dep)
) -> InvestigationOut:
    return InvestigationOut.model_validate(await _get_or_404(db, inv_id))


@router.get("/investigation/{inv_id}/provider-runs", summary="Every provider call made by the investigation")
async def provider_runs(
    inv_id: str, _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)), db=Depends(db_dep)
) -> list[dict[str, Any]]:
    doc = await InvestigationRepository(db).get(inv_id, {"provider_runs": 1})
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return doc.get("provider_runs", [])


@router.get(
    "/investigation/{inv_id}/assets", response_model=Page[AssetListItem], summary="Assets found by an investigation"
)
async def investigation_assets(
    inv_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    asset_type: str | None = Query(None, alias="type"),
    _: CurrentUser = Depends(require(Permission.ASSET_READ)),
    db=Depends(db_dep),
) -> Page[AssetListItem]:
    query: dict[str, Any] = {"investigation_ids": inv_id}
    if asset_type:
        query["type"] = asset_type
    skip, limit = paginate(page, page_size)
    items, total = await AssetRepository(db).find_page(
        query,
        sort=[("confidence", -1), ("last_seen", -1)],
        skip=skip,
        limit=limit,
        projection={"enrichment": 0, "correlation": 0},
    )
    return Page(items=[AssetListItem.model_validate(i) for i in items], total=total, page=page, page_size=limit)


@router.get("/investigation/{inv_id}/artifacts", response_model=list[ArtifactOut], summary="Raw collected artifacts")
async def investigation_artifacts(
    inv_id: str,
    kind: list[str] | None = Query(None),
    include_data: bool = False,
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)),
    db=Depends(db_dep),
) -> list[ArtifactOut]:
    docs = await ArtifactRepository(db, get_fs()).for_investigation(inv_id, kind)
    out = []
    for d in docs:
        if not include_data and str(d.get("kind", "")).startswith("provider:"):
            d = {**d, "data": None}
        out.append(ArtifactOut.model_validate(d))
    return out


@router.post("/investigation/{inv_id}/cancel", response_model=Message, summary="Cancel a queued/running investigation")
async def cancel_investigation(
    inv_id: str,
    request: Request,
    user: CurrentUser = Depends(require(Permission.INVESTIGATION_WRITE)),
    runner: PipelineRunner = Depends(runner_dep),
    db=Depends(db_dep),
) -> Message:
    await _get_or_404(db, inv_id)
    if not await runner.cancel(inv_id):
        raise HTTPException(status.HTTP_409_CONFLICT, "Investigation is not running")
    await audit(
        "investigation.cancel",
        username=user.username,
        role=user.role,
        resource_type="investigation",
        resource_id=inv_id,
        ip=client_ip(request),
    )
    return Message(message="Cancellation requested")


@router.post(
    "/investigation/{inv_id}/rerun",
    response_model=InvestigationOut,
    status_code=202,
    summary="Re-run an investigation with the same IOC and options",
)
async def rerun_investigation(
    inv_id: str,
    request: Request,
    user: CurrentUser = Depends(require(Permission.INVESTIGATION_WRITE)),
    runner: PipelineRunner = Depends(runner_dep),
    db=Depends(db_dep),
) -> InvestigationOut:
    from app.models.investigation import InvestigationOptions

    old = await _get_or_404(db, inv_id)
    doc = runner.new_document(
        old["normalized"],
        InvestigationOptions.model_validate(old.get("options") or {}),
        created_by=user.username,
        tags=old.get("tags"),
        case_id=old.get("case_id"),
    )
    await runner.submit(doc)
    await audit(
        "investigation.rerun",
        username=user.username,
        role=user.role,
        resource_type="investigation",
        resource_id=doc["_id"],
        ip=client_ip(request),
        details={"previous": inv_id},
    )
    return InvestigationOut.model_validate(doc)


@router.post("/investigation/{inv_id}/notes", response_model=InvestigationOut, summary="Add an analyst note")
async def add_note(
    inv_id: str,
    body: InvestigationNote,
    user: CurrentUser = Depends(require(Permission.INVESTIGATION_WRITE)),
    db=Depends(db_dep),
) -> InvestigationOut:
    await _get_or_404(db, inv_id)
    note = {"id": new_id("note_"), "text": body.text, "author": user.username, "created_at": utcnow()}
    doc = await InvestigationRepository(db).add_note(inv_id, note)
    assert doc is not None
    doc.pop("provider_runs", None)
    return InvestigationOut.model_validate(doc)


@router.delete("/investigation/{inv_id}", response_model=Message, summary="Delete an investigation and its artifacts")
async def delete_investigation(
    inv_id: str,
    request: Request,
    user: CurrentUser = Depends(require(Permission.INVESTIGATION_WRITE)),
    runner: PipelineRunner = Depends(runner_dep),
    db=Depends(db_dep),
) -> Message:
    doc = await _get_or_404(db, inv_id)
    if doc["status"] in (InvestigationStatus.RUNNING.value, InvestigationStatus.QUEUED.value):
        await runner.cancel(inv_id)
    removed = await ArtifactRepository(db, get_fs()).delete_for_investigation(inv_id)
    await db["assets"].update_many({"investigation_ids": inv_id}, {"$pull": {"investigation_ids": inv_id}})
    await db["relationships"].update_many({"investigation_ids": inv_id}, {"$pull": {"investigation_ids": inv_id}})
    await InvestigationRepository(db).delete(inv_id)
    await audit(
        "investigation.delete",
        username=user.username,
        role=user.role,
        resource_type="investigation",
        resource_id=inv_id,
        ip=client_ip(request),
        details={"artifacts_removed": removed},
    )
    return Message(message="Investigation deleted", detail={"artifacts_removed": removed})
