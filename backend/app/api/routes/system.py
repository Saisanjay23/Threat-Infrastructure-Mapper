"""Dashboard, audit logs, health and metrics."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse

from app.api.deps import db_dep, require
from app.collectors.browser import BrowserEngine
from app.core.config import get_settings
from app.core.security import Permission
from app.db.mongo import Collections, Mongo
from app.models.audit import AuditLogOut
from app.models.common import Page
from app.models.user import CurrentUser
from app.repositories.base import paginate
from app.services.dashboard import build_dashboard
from app.services.metrics import render_prometheus
from app.services.progress import hub

router = APIRouter(tags=["System"])


@router.get("/dashboard", summary="Dashboard statistics, recent investigations, clusters and screenshots")
async def dashboard(
    _: CurrentUser = Depends(require(Permission.INVESTIGATION_READ)), db=Depends(db_dep)
) -> dict[str, Any]:
    return await build_dashboard(db)


@router.get("/audit-logs", response_model=Page[AuditLogOut], summary="Audit trail")
async def audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    username: str | None = None,
    action: str | None = None,
    status: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    _: CurrentUser = Depends(require(Permission.AUDIT_READ)),
    db=Depends(db_dep),
) -> Page[AuditLogOut]:
    query: dict[str, Any] = {}
    if username:
        query["username"] = username.lower()
    if action:
        query["action"] = {"$regex": "^" + re.escape(action)}
    if status:
        query["status"] = status
    if since or until:
        query["timestamp"] = {k: v for k, v in (("$gte", since), ("$lte", until)) if v}
    skip, limit = paginate(page, page_size)
    col = db[Collections.AUDIT_LOGS]
    docs = await col.find(query).sort("timestamp", -1).skip(skip).limit(limit).to_list(length=limit)
    total = await col.count_documents(query)
    return Page(items=[AuditLogOut.model_validate(d) for d in docs], total=total, page=page, page_size=limit)


@router.get("/health", summary="Liveness / readiness")
async def health(request: Request) -> dict[str, Any]:
    settings = get_settings()
    mongo_ok = False
    mongo_error = None
    try:
        if Mongo.client is not None:
            await Mongo.client.admin.command("ping")
            mongo_ok = True
    except Exception as exc:
        mongo_error = str(exc)
    browser = BrowserEngine.instance()
    return {
        "status": "ok" if mongo_ok else "degraded",
        "version": settings.version,
        "environment": settings.environment,
        "mongodb": {"ok": mongo_ok, "database": settings.mongo_db, "error": mongo_error},
        "browser": {
            "available": browser.available,
            "last_error": browser.last_error,
            "enabled": settings.screenshots_enabled,
        },
        "pipeline": request.app.state.runner.active() if hasattr(request.app.state, "runner") else None,
        "websocket_subscribers": hub.subscriber_count(),
    }


@router.get("/metrics", response_class=PlainTextResponse, summary="Prometheus metrics")
async def prometheus_metrics(db=Depends(db_dep)) -> str:
    gauges: dict[str, float] = {
        "investigations_total": await db[Collections.INVESTIGATIONS].estimated_document_count(),
        "investigations_running": await db[Collections.INVESTIGATIONS].count_documents({"status": "running"}),
        "investigations_queued": await db[Collections.INVESTIGATIONS].count_documents({"status": "queued"}),
        "assets_total": await db[Collections.ASSETS].estimated_document_count(),
        "relationships_total": await db[Collections.RELATIONSHIPS].estimated_document_count(),
        "clusters_total": await db[Collections.CLUSTERS].estimated_document_count(),
        "provider_cache_entries": await db[Collections.PROVIDER_CACHE].estimated_document_count(),
        "websocket_subscribers": hub.subscriber_count(),
    }
    return render_prometheus(gauges)
