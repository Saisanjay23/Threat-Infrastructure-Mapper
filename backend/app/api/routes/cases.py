"""Case management: create cases, attach assets/investigations/clusters, notes, tags, severity."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pymongo import ReturnDocument

from app.api.deps import client_ip, db_dep, require
from app.core.security import Permission
from app.db.mongo import Collections
from app.models.case import CaseCreate, CaseLinks, CaseListItem, CaseNote, CaseOut, CaseUpdate
from app.models.common import Message, Page, new_id, utcnow
from app.models.user import CurrentUser
from app.repositories.base import paginate
from app.services.audit import audit

router = APIRouter(prefix="/cases", tags=["Cases"])


async def _next_case_id(db) -> str:
    year = utcnow().year
    counter = await db[Collections.SETTINGS].find_one_and_update(
        {"_id": f"case_counter_{year}"}, {"$inc": {"value": 1}}, upsert=True, return_document=ReturnDocument.AFTER
    )
    return f"CASE-{year}-{int(counter['value']):04d}"


def _tags(tags: list[str]) -> list[str]:
    return sorted({t.strip().lower() for t in tags if t.strip()})


async def _validate_links(db, links: CaseLinks | CaseCreate) -> None:
    for collection, ids, label in (
        (Collections.ASSETS, links.asset_ids, "asset"),
        (Collections.INVESTIGATIONS, links.investigation_ids, "investigation"),
        (Collections.CLUSTERS, links.cluster_ids, "cluster"),
    ):
        if ids:
            found = await db[collection].count_documents({"_id": {"$in": ids}})
            if found != len(set(ids)):
                raise HTTPException(422, f"one or more {label} ids do not exist")


async def _get(db, case_id: str) -> dict[str, Any]:
    doc = await db[Collections.CASES].find_one({"_id": case_id})
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    return doc


@router.post("", response_model=CaseOut, status_code=201, summary="Create a case")
async def create_case(
    body: CaseCreate, request: Request, user: CurrentUser = Depends(require(Permission.CASE_WRITE)), db=Depends(db_dep)
) -> CaseOut:
    await _validate_links(db, body)
    now = utcnow()
    doc = {
        "_id": await _next_case_id(db),
        "title": body.title,
        "description": body.description,
        "severity": body.severity.value,
        "status": "open",
        "tags": _tags(body.tags),
        "assignee": body.assignee,
        "asset_ids": sorted(set(body.asset_ids)),
        "investigation_ids": sorted(set(body.investigation_ids)),
        "cluster_ids": sorted(set(body.cluster_ids)),
        "notes": [],
        "created_by": user.username,
        "created_at": now,
        "updated_at": now,
    }
    await db[Collections.CASES].insert_one(doc)
    if doc["investigation_ids"]:
        await db[Collections.INVESTIGATIONS].update_many(
            {"_id": {"$in": doc["investigation_ids"]}}, {"$set": {"case_id": doc["_id"]}}
        )
    await audit(
        "case.create",
        username=user.username,
        role=user.role,
        resource_type="case",
        resource_id=str(doc["_id"]),
        ip=client_ip(request),
        details={"title": body.title},
    )
    return CaseOut.model_validate(doc)


@router.get("", response_model=Page[CaseListItem], summary="List cases")
async def list_cases(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    q: str | None = Query(None, max_length=200),
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    tag: str | None = None,
    asset_id: str | None = None,
    _: CurrentUser = Depends(require(Permission.CASE_READ)),
    db=Depends(db_dep),
) -> Page[CaseListItem]:
    query: dict[str, Any] = {}
    if q:
        rx = {"$regex": re.escape(q.strip()), "$options": "i"}
        query["$or"] = [{"title": rx}, {"_id": rx}, {"description": rx}]
    if status_filter:
        query["status"] = status_filter
    if severity:
        query["severity"] = severity
    if tag:
        query["tags"] = tag.lower()
    if asset_id:
        query["asset_ids"] = asset_id
    skip, limit = paginate(page, page_size)
    col = db[Collections.CASES]
    docs = await col.find(query, {"notes": 0}).sort("updated_at", -1).skip(skip).limit(limit).to_list(length=limit)
    items = [
        CaseListItem.model_validate(
            {
                **d,
                "asset_count": len(d.get("asset_ids", [])),
                "investigation_count": len(d.get("investigation_ids", [])),
                "cluster_count": len(d.get("cluster_ids", [])),
            }
        )
        for d in docs
    ]
    return Page(items=items, total=await col.count_documents(query), page=page, page_size=limit)


@router.get("/{case_id}", response_model=CaseOut, summary="Case detail")
async def get_case(
    case_id: str, _: CurrentUser = Depends(require(Permission.CASE_READ)), db=Depends(db_dep)
) -> CaseOut:
    return CaseOut.model_validate(await _get(db, case_id))


@router.patch(
    "/{case_id}", response_model=CaseOut, summary="Update title, description, severity, status, tags, assignee"
)
async def update_case(
    case_id: str,
    body: CaseUpdate,
    request: Request,
    user: CurrentUser = Depends(require(Permission.CASE_WRITE)),
    db=Depends(db_dep),
) -> CaseOut:
    await _get(db, case_id)
    fields = body.model_dump(exclude_none=True)
    if "tags" in fields:
        fields["tags"] = _tags(fields["tags"])
    if "severity" in fields:
        fields["severity"] = str(fields["severity"])
    fields["updated_at"] = utcnow()
    doc = await db[Collections.CASES].find_one_and_update(
        {"_id": case_id}, {"$set": fields}, return_document=ReturnDocument.AFTER
    )
    await audit(
        "case.update",
        username=user.username,
        role=user.role,
        resource_type="case",
        resource_id=case_id,
        ip=client_ip(request),
        details={k: v for k, v in fields.items() if k != "updated_at"},
    )
    return CaseOut.model_validate(doc)


@router.post("/{case_id}/links", response_model=CaseOut, summary="Add assets, investigations or clusters to a case")
async def add_links(
    case_id: str,
    body: CaseLinks,
    request: Request,
    user: CurrentUser = Depends(require(Permission.CASE_WRITE)),
    db=Depends(db_dep),
) -> CaseOut:
    await _get(db, case_id)
    await _validate_links(db, body)
    doc = await db[Collections.CASES].find_one_and_update(
        {"_id": case_id},
        {
            "$addToSet": {
                "asset_ids": {"$each": body.asset_ids},
                "investigation_ids": {"$each": body.investigation_ids},
                "cluster_ids": {"$each": body.cluster_ids},
            },
            "$set": {"updated_at": utcnow()},
        },
        return_document=ReturnDocument.AFTER,
    )
    if body.investigation_ids:
        await db[Collections.INVESTIGATIONS].update_many(
            {"_id": {"$in": body.investigation_ids}}, {"$set": {"case_id": case_id}}
        )
    await audit(
        "case.link",
        username=user.username,
        role=user.role,
        resource_type="case",
        resource_id=case_id,
        ip=client_ip(request),
        details={
            "assets": len(body.asset_ids),
            "investigations": len(body.investigation_ids),
            "clusters": len(body.cluster_ids),
        },
    )
    return CaseOut.model_validate(doc)


@router.post(
    "/{case_id}/unlink", response_model=CaseOut, summary="Remove assets, investigations or clusters from a case"
)
async def remove_links(
    case_id: str, body: CaseLinks, user: CurrentUser = Depends(require(Permission.CASE_WRITE)), db=Depends(db_dep)
) -> CaseOut:
    await _get(db, case_id)
    doc = await db[Collections.CASES].find_one_and_update(
        {"_id": case_id},
        {
            "$pull": {
                "asset_ids": {"$in": body.asset_ids},
                "investigation_ids": {"$in": body.investigation_ids},
                "cluster_ids": {"$in": body.cluster_ids},
            },
            "$set": {"updated_at": utcnow()},
        },
        return_document=ReturnDocument.AFTER,
    )
    if body.investigation_ids:
        await db[Collections.INVESTIGATIONS].update_many(
            {"_id": {"$in": body.investigation_ids}, "case_id": case_id}, {"$set": {"case_id": None}}
        )
    return CaseOut.model_validate(doc)


@router.post("/{case_id}/notes", response_model=CaseOut, summary="Add a case note")
async def add_case_note(
    case_id: str, body: CaseNote, user: CurrentUser = Depends(require(Permission.CASE_WRITE)), db=Depends(db_dep)
) -> CaseOut:
    await _get(db, case_id)
    note = {"id": new_id("note_"), "text": body.text, "author": user.username, "created_at": utcnow()}
    doc = await db[Collections.CASES].find_one_and_update(
        {"_id": case_id},
        {"$push": {"notes": note}, "$set": {"updated_at": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    return CaseOut.model_validate(doc)


@router.delete("/{case_id}", response_model=Message, summary="Delete a case (linked data is kept)")
async def delete_case(
    case_id: str, request: Request, user: CurrentUser = Depends(require(Permission.CASE_WRITE)), db=Depends(db_dep)
) -> Message:
    await _get(db, case_id)
    await db[Collections.CASES].delete_one({"_id": case_id})
    await db[Collections.INVESTIGATIONS].update_many({"case_id": case_id}, {"$set": {"case_id": None}})
    await audit(
        "case.delete",
        username=user.username,
        role=user.role,
        resource_type="case",
        resource_id=case_id,
        ip=client_ip(request),
    )
    return Message(message="Case deleted")
