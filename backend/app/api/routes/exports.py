"""Report generation (PDF / HTML / CSV / JSON) and the report library."""

from __future__ import annotations

import asyncio
import re
from typing import Literal

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from gridfs.errors import NoFile

from app.api.deps import client_ip, db_dep, get_current_user_or_query, require
from app.core.security import Permission
from app.db.mongo import Collections, get_fs
from app.models.case import ExportRequest, ReportOut
from app.models.common import Message, Page, new_id, utcnow
from app.models.user import CurrentUser
from app.reporting.data import ReportScopeError, build_report_data
from app.reporting.html_report import render_html
from app.reporting.pdf import render_pdf
from app.reporting.tabular import render_csv, render_json
from app.repositories.artifacts import ArtifactRepository
from app.repositories.base import paginate
from app.services.audit import audit

router = APIRouter(tags=["Reporting"])
Format = Literal["pdf", "html", "csv", "json"]
MEDIA = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
}


def _filename(title: str, fmt: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", title).strip("-")[:80] or "tim-report"
    return f"{slug}-{utcnow():%Y%m%d-%H%M}.{fmt}"


async def _export(fmt: Format, body: ExportRequest, request: Request, user: CurrentUser, db) -> Response:
    try:
        data = await build_report_data(db, get_fs(), body, user.username)
    except ReportScopeError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    renderers = {"pdf": render_pdf, "html": render_html, "csv": render_csv, "json": render_json}
    content = await asyncio.to_thread(renderers[fmt], data)
    filename = _filename(data.title, fmt)
    report_id = None
    if body.save:
        art = await ArtifactRepository(db, get_fs()).store_file(
            f"report_{fmt}",
            content,
            filename=filename,
            content_type=MEDIA[fmt],
            investigation_id=body.investigation_id,
            metadata={"scope": data.scope_type, "scope_id": data.scope_id},
        )
        report_id = new_id("rpt_")
        await db[Collections.REPORTS].insert_one(
            {
                "_id": report_id,
                "title": data.title,
                "format": fmt,
                "scope_type": data.scope_type,
                "scope_id": data.scope_id,
                "size": len(content),
                "file_id": art["file_id"],
                "filename": filename,
                "sections": list(body.sections),
                "tlp": body.tlp,
                "created_by": user.username,
                "created_at": utcnow(),
            }
        )
    await audit(
        f"export.{fmt}",
        username=user.username,
        role=user.role,
        resource_type=data.scope_type,
        resource_id=data.scope_id,
        ip=client_ip(request),
        details={"assets": len(data.assets), "bytes": len(content), "report_id": report_id},
    )
    headers = {"Content-Disposition": f'attachment; filename="{filename}"', "X-Content-Type-Options": "nosniff"}
    if report_id:
        headers["X-Report-Id"] = report_id
    return Response(content=content, media_type=MEDIA[fmt], headers=headers)


@router.post(
    "/export/pdf",
    response_class=Response,
    summary="Generate a PDF analyst report",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def export_pdf(
    body: ExportRequest,
    request: Request,
    user: CurrentUser = Depends(require(Permission.REPORT_EXPORT)),
    db=Depends(db_dep),
) -> Response:
    return await _export("pdf", body, request, user, db)


@router.post(
    "/export/html",
    response_class=Response,
    summary="Generate a self-contained HTML report (print to PDF)",
    responses={200: {"content": {"text/html": {}}}},
)
async def export_html(
    body: ExportRequest,
    request: Request,
    user: CurrentUser = Depends(require(Permission.REPORT_EXPORT)),
    db=Depends(db_dep),
) -> Response:
    return await _export("html", body, request, user, db)


@router.post(
    "/export/csv",
    response_class=Response,
    summary="Export related assets as CSV",
    responses={200: {"content": {"text/csv": {}}}},
)
async def export_csv(
    body: ExportRequest,
    request: Request,
    user: CurrentUser = Depends(require(Permission.REPORT_EXPORT)),
    db=Depends(db_dep),
) -> Response:
    return await _export("csv", body, request, user, db)


@router.post(
    "/export/json",
    response_class=Response,
    summary="Export the full investigation data model as JSON",
    responses={200: {"content": {"application/json": {}}}},
)
async def export_json(
    body: ExportRequest,
    request: Request,
    user: CurrentUser = Depends(require(Permission.REPORT_EXPORT)),
    db=Depends(db_dep),
) -> Response:
    return await _export("json", body, request, user, db)


@router.get("/reports", response_model=Page[ReportOut], summary="Report library")
async def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    scope_id: str | None = None,
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)),
    db=Depends(db_dep),
) -> Page[ReportOut]:
    query = {"scope_id": scope_id} if scope_id else {}
    skip, limit = paginate(page, page_size)
    col = db[Collections.REPORTS]
    docs = await col.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(length=limit)
    return Page(
        items=[ReportOut.model_validate(d) for d in docs],
        total=await col.count_documents(query),
        page=page,
        page_size=limit,
    )


@router.get("/reports/{report_id}/download", response_class=Response, summary="Download a stored report")
async def download_report(
    report_id: str, _: CurrentUser = Depends(get_current_user_or_query), db=Depends(db_dep)
) -> Response:
    doc = await db[Collections.REPORTS].find_one({"_id": report_id})
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    found = await ArtifactRepository(db, get_fs()).read_file(doc["file_id"])
    if not found:
        raise HTTPException(status.HTTP_410_GONE, "Report file missing")
    return Response(
        content=found[0],
        media_type=MEDIA.get(doc["format"], "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{doc["filename"]}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/reports/{report_id}", response_model=Message, summary="Delete a stored report")
async def delete_report(
    report_id: str, request: Request, user: CurrentUser = Depends(require(Permission.REPORT_EXPORT)), db=Depends(db_dep)
) -> Message:
    doc = await db[Collections.REPORTS].find_one_and_delete({"_id": report_id})
    if not doc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    try:
        await get_fs().delete(ObjectId(doc["file_id"]))
    except (NoFile, InvalidId):
        pass
    await db[Collections.ARTIFACTS].delete_many({"file_id": doc["file_id"]})
    await audit(
        "report.delete",
        username=user.username,
        role=user.role,
        resource_type="report",
        resource_id=report_id,
        ip=client_ip(request),
    )
    return Message(message="Report deleted")
