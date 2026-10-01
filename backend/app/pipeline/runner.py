"""Investigation orchestrator: queueing, concurrency, stage execution, cancellation and recovery."""

from __future__ import annotations

import asyncio
import logging
import traceback
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import get_settings
from app.db.mongo import get_fs
from app.models.common import new_id, utcnow
from app.models.investigation import (
    STAGE_ORDER,
    InvestigationOptions,
    InvestigationStatus,
    StageName,
    StageStatus,
)
from app.pipeline.context import InvestigationCancelledError, InvestigationContext
from app.pipeline.stages.base import Stage
from app.providers.manager import ProviderManager
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.repositories.base import Doc
from app.repositories.investigations import InvestigationRepository
from app.repositories.relationships import RelationshipRepository
from app.services.progress import ProgressHub
from app.utils.ioc import parse_ioc

log = logging.getLogger(__name__)


def default_stages() -> list[Stage]:
    from app.pipeline.stages.collection import CollectionStage
    from app.pipeline.stages.correlation import CorrelationStage
    from app.pipeline.stages.enrichment import EnrichmentStage
    from app.pipeline.stages.pivot import PivotStage

    return [CollectionStage(), EnrichmentStage(), PivotStage(), CorrelationStage()]


async def compute_investigation_summary(db: AsyncIOMotorDatabase, inv_id: str) -> dict[str, Any]:
    assets = db["assets"]
    pipeline: list[dict[str, Any]] = [
        {"$match": {"investigation_ids": inv_id}},
        {"$group": {"_id": "$type", "n": {"$sum": 1}}},
    ]
    counts = {d["_id"]: d["n"] async for d in assets.aggregate(pipeline)}
    relationships = await db["relationships"].count_documents({"investigation_ids": inv_id})
    clusters = await db["clusters"].count_documents({"investigation_ids": inv_id})
    high = await assets.count_documents({"investigation_ids": inv_id, "confidence": {"$gte": 70}})
    top = await assets.find_one(
        {"investigation_ids": inv_id, "confidence": {"$ne": None}},
        sort=[("confidence", -1)],
        projection={"confidence": 1},
    )
    doc = await db["investigations"].find_one({"_id": inv_id}, {"root_asset_id": 1})
    root = await assets.find_one({"_id": doc["root_asset_id"]}) if doc and doc.get("root_asset_id") else None
    host = root
    if root and root.get("type") == "url":
        host = await assets.find_one(
            {"investigation_ids": inv_id, "type": {"$in": ["domain", "ip"]}, "attributes.web": {"$exists": True}}
        )
    return {
        "assets_discovered": sum(counts.values()),
        "domains": counts.get("domain", 0),
        "ips": counts.get("ip", 0),
        "certificates": counts.get("certificate", 0),
        "tracking_ids": counts.get("analytics", 0) + counts.get("pixel", 0) + counts.get("tracking", 0),
        "relationships": relationships,
        "clusters": clusters,
        "high_confidence": high,
        "site_status": (host or {}).get("status"),
        "impersonation_score": (host or {}).get("impersonation_score"),
        "max_confidence": int((top or {}).get("confidence") or 0),
    }


class PipelineRunner:
    def __init__(
        self, db: AsyncIOMotorDatabase, providers: ProviderManager, hub: ProgressHub, stages: list[Stage] | None = None
    ) -> None:
        self.db = db
        self.providers = providers
        self.hub = hub
        self.stages: dict[StageName, Stage] = {s.name: s for s in (stages or default_stages())}
        self.repo = InvestigationRepository(db)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._cancel: dict[str, asyncio.Event] = {}
        self._sem = asyncio.Semaphore(get_settings().max_concurrent_investigations)

    # ------------------------------------------------------------------ creation
    def new_document(
        self,
        raw_ioc: str,
        options: InvestigationOptions,
        *,
        created_by: str,
        tags: list[str] | None = None,
        case_id: str | None = None,
        bulk_id: str | None = None,
    ) -> Doc:
        parsed = parse_ioc(raw_ioc)
        now = utcnow()
        return {
            "_id": new_id("inv_"),
            "ioc": raw_ioc.strip(),
            "ioc_type": parsed.type.value,
            "normalized": parsed.value,
            "status": InvestigationStatus.QUEUED.value,
            "options": options.model_dump(),
            "stages": InvestigationRepository.initial_stages(),
            "summary": {},
            "root_asset_id": None,
            "tags": sorted({t.strip().lower() for t in tags or [] if t.strip()}),
            "case_id": case_id,
            "bulk_id": bulk_id,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "finished_at": None,
            "error": None,
            "notes": [],
            "provider_runs": [],
        }

    async def submit(self, doc: Doc) -> Doc:
        await self.repo.insert(doc)
        self.schedule(doc["_id"])
        await self.hub.publish(
            doc["_id"],
            {
                "type": "investigation_queued",
                "investigation_id": doc["_id"],
                "ioc": doc["normalized"],
                "timestamp": utcnow(),
            },
        )
        return doc

    def schedule(self, inv_id: str) -> None:
        if inv_id in self._tasks and not self._tasks[inv_id].done():
            return
        self._cancel[inv_id] = asyncio.Event()
        task = asyncio.create_task(self._run(inv_id), name=f"investigation:{inv_id}")
        self._tasks[inv_id] = task
        task.add_done_callback(lambda _t: (self._tasks.pop(inv_id, None), self._cancel.pop(inv_id, None)))

    async def cancel(self, inv_id: str) -> bool:
        event = self._cancel.get(inv_id)
        doc = await self.repo.get(inv_id, {"status": 1})
        if doc and doc["status"] == InvestigationStatus.QUEUED.value and event:
            event.set()
            return True
        if event:
            event.set()
            return True
        return False

    def active(self) -> dict[str, int]:
        return {"tracked": len(self._tasks)}

    # ------------------------------------------------------------------ lifecycle
    async def recover(self) -> int:
        """Re-queue investigations interrupted by a restart."""
        cursor = self.repo.col.find(
            {"status": {"$in": [InvestigationStatus.QUEUED.value, InvestigationStatus.RUNNING.value]}}, {"_id": 1}
        )
        ids = [d["_id"] async for d in cursor]
        for inv_id in ids:
            await self.repo.update(
                inv_id, {"status": InvestigationStatus.QUEUED.value, "stages": InvestigationRepository.initial_stages()}
            )
            self.schedule(inv_id)
        if ids:
            log.info("Re-queued %d interrupted investigation(s)", len(ids))
        return len(ids)

    async def shutdown(self) -> None:
        for event in self._cancel.values():
            event.set()
        tasks = list(self._tasks.values())
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def wait(self, inv_id: str, timeout: float | None = None) -> None:
        task = self._tasks.get(inv_id)
        if task:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)

    # ------------------------------------------------------------------ execution
    def _context(self, doc: Doc, cancel_event: asyncio.Event) -> InvestigationContext:
        return InvestigationContext(
            inv=doc,
            ioc=parse_ioc(doc["normalized"]),
            options=InvestigationOptions.model_validate(doc.get("options") or {}),
            db=self.db,
            providers=self.providers,
            assets=AssetRepository(self.db),
            artifacts=ArtifactRepository(self.db, get_fs()),
            relationships=RelationshipRepository(self.db),
            investigations=self.repo,
            hub=self.hub,
            cancel_event=cancel_event,
        )

    async def _set_status(self, inv_id: str, status: InvestigationStatus, **fields: Any) -> None:
        await self.repo.update(inv_id, {"status": status.value, **fields})
        await self.hub.publish(
            inv_id,
            {
                "type": "investigation_status",
                "investigation_id": inv_id,
                "status": status.value,
                "timestamp": utcnow(),
                **fields,
            },
        )

    async def _run(self, inv_id: str) -> None:
        cancel_event = self._cancel.get(inv_id) or asyncio.Event()
        async with self._sem:
            doc = await self.repo.get(inv_id)
            if doc is None:
                return
            if cancel_event.is_set():
                await self._set_status(inv_id, InvestigationStatus.CANCELLED, finished_at=utcnow())
                return
            ctx = self._context(doc, cancel_event)
            await self._set_status(inv_id, InvestigationStatus.RUNNING, started_at=utcnow())
            failed_stages: list[str] = []
            try:
                for stage_name in STAGE_ORDER:
                    stage = self.stages.get(stage_name)
                    if stage is None:
                        await self.repo.set_stage(
                            inv_id, stage_name.value, status=StageStatus.SKIPPED.value, message="Stage not enabled"
                        )
                        continue
                    if stage_name != StageName.COLLECTION and ctx.root_asset is None:
                        await self.repo.set_stage(
                            inv_id, stage_name.value, status=StageStatus.SKIPPED.value, message="No root asset"
                        )
                        continue
                    ok = await self._run_stage(ctx, stage)
                    if not ok:
                        failed_stages.append(stage_name.value)
                        if stage_name == StageName.COLLECTION and ctx.root_asset is None:
                            break
                summary = await self.compute_summary(inv_id)
                status = InvestigationStatus.FAILED if ctx.root_asset is None else InvestigationStatus.COMPLETED
                error = f"stage(s) failed: {', '.join(failed_stages)}" if failed_stages else None
                await self._set_status(inv_id, status, finished_at=utcnow(), summary=summary, error=error)
            except InvestigationCancelledError:
                await self._mark_running_stages(inv_id, StageStatus.FAILED, "Cancelled")
                await self._set_status(
                    inv_id,
                    InvestigationStatus.CANCELLED,
                    finished_at=utcnow(),
                    summary=await self.compute_summary(inv_id),
                )
            except asyncio.CancelledError:
                await self._set_status(inv_id, InvestigationStatus.QUEUED)
                raise
            except Exception as exc:
                log.exception("Investigation %s crashed", inv_id)
                await self._set_status(
                    inv_id, InvestigationStatus.FAILED, finished_at=utcnow(), error=f"{type(exc).__name__}: {exc}"
                )

    async def _run_stage(self, ctx: InvestigationContext, stage: Stage) -> bool:
        name = stage.name.value
        await self.repo.set_stage(ctx.id, name, status=StageStatus.RUNNING.value, started_at=utcnow(), progress=0)
        await self.hub.publish(
            ctx.id, {"type": "stage_started", "investigation_id": ctx.id, "stage": name, "timestamp": utcnow()}
        )
        try:
            message = await stage.run(ctx)
        except InvestigationCancelledError:
            raise
        except Exception as exc:
            log.error("Stage %s failed for %s: %s\n%s", name, ctx.id, exc, traceback.format_exc())
            await ctx.log(name, f"Stage failed: {type(exc).__name__}: {exc}", "error")
            await self.repo.set_stage(
                ctx.id,
                name,
                status=StageStatus.FAILED.value,
                finished_at=utcnow(),
                message=f"{type(exc).__name__}: {exc}"[:500],
            )
            await self.hub.publish(
                ctx.id,
                {
                    "type": "stage_failed",
                    "investigation_id": ctx.id,
                    "stage": name,
                    "error": str(exc)[:500],
                    "timestamp": utcnow(),
                },
            )
            return False
        await self.repo.set_stage(
            ctx.id, name, status=StageStatus.COMPLETED.value, progress=100, finished_at=utcnow(), message=message
        )
        await self.hub.publish(
            ctx.id,
            {
                "type": "stage_completed",
                "investigation_id": ctx.id,
                "stage": name,
                "message": message,
                "timestamp": utcnow(),
            },
        )
        return True

    async def _mark_running_stages(self, inv_id: str, status: StageStatus, message: str) -> None:
        doc = await self.repo.get(inv_id, {"stages": 1})
        for name, state in (doc or {}).get("stages", {}).items():
            if state.get("status") in (StageStatus.RUNNING.value, StageStatus.PENDING.value):
                await self.repo.set_stage(
                    inv_id,
                    name,
                    status=status.value if state.get("status") == "running" else StageStatus.SKIPPED.value,
                    message=message,
                    finished_at=utcnow(),
                )

    async def compute_summary(self, inv_id: str) -> dict[str, Any]:
        return await compute_investigation_summary(self.db, inv_id)
