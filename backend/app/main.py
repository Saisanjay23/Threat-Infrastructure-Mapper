"""FastAPI application factory for the Threat Infrastructure Mapper."""

from __future__ import annotations

import logging
import warnings
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import assets, auth, cases, exports, graph, investigations, providers, system, uploads, ws
from app.collectors.browser import BrowserEngine
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.mongo import Mongo
from app.pipeline.runner import PipelineRunner
from app.providers.manager import ProviderManager
from app.services.bootstrap import ensure_admin
from app.services.metrics import MetricsMiddleware
from app.services.progress import hub

log = logging.getLogger("tim")

TAGS = [
    {"name": "Authentication", "description": "JWT login. Send `Authorization: Bearer <token>` on every request."},
    {"name": "Investigations", "description": "Turn a single IOC into an infrastructure investigation."},
    {"name": "Assets", "description": "Discovered infrastructure: domains, URLs, IPs, certificates, trackers..."},
    {"name": "Graph & Clusters", "description": "NetworkX relationship graphs, threat clusters and scoring model."},
    {"name": "Cases", "description": "Case management: assets, investigations, clusters, notes, tags, severity."},
    {"name": "Reporting", "description": "PDF / HTML / CSV / JSON exports and the report library."},
    {
        "name": "Uploads",
        "description": "Logo, HTML, screenshot and certificate uploads as pivots and brand references.",
    },
    {"name": "Providers", "description": "Intelligence source management (keys, priorities, health, usage, cache)."},
    {"name": "Realtime", "description": "WebSocket progress streams."},
    {"name": "System", "description": "Dashboard, audit trail, health and Prometheus metrics."},
    {"name": "Users", "description": "User administration (admin only)."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.debug)
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    db = await Mongo.connect()
    await ensure_admin(db)
    manager = ProviderManager(db)
    await manager.startup()
    runner = PipelineRunner(db, manager, hub)
    app.state.providers = manager
    app.state.runner = runner
    if not settings.is_test:
        await runner.recover()
    log.info(
        "%s %s ready on http://%s:%s (docs at /docs)", settings.app_name, settings.version, settings.host, settings.port
    )
    try:
        yield
    finally:
        await runner.shutdown()
        await BrowserEngine.instance().shutdown()
        await manager.shutdown()
        await Mongo.close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Threat Infrastructure Mapper (TIM) API",
        version=settings.version,
        description=(
            "Local-first threat intelligence and infrastructure mapping. Submit one IOC and TIM collects, "
            "fingerprints, enriches, pivots and correlates the infrastructure that belongs to the same operation."
        ),
        openapi_tags=TAGS,
        lifespan=lifespan,
    )
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )
    api_router = APIRouter(prefix="/api")
    for module in (auth, investigations, assets, graph, cases, exports, uploads, providers, system, ws):
        app.include_router(module.router)
        api_router.include_router(module.router)
    app.include_router(auth.users_router)
    api_router.include_router(auth.users_router)
    app.include_router(api_router)

    # Mount frontend static distribution if built
    dist_dir = (Path(__file__).resolve().parents[2] / "frontend" / "dist").resolve()
    if dist_dir.exists() and (dist_dir / "index.html").exists():
        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="spa_assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str):
            if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
                raise HTTPException(status_code=404, detail="Not found")
            file_path = dist_dir / full_path
            if full_path and file_path.is_file():
                return FileResponse(file_path)
            return FileResponse(dist_dir / "index.html")

    return app


app = create_app()
