"""Shared state and helpers passed between pipeline stages."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.common import AssetType, utcnow
from app.models.graph import RelatedEntity, RelationType
from app.models.investigation import InvestigationOptions
from app.providers.manager import ProviderManager, ProviderRun
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.repositories.base import Doc
from app.repositories.investigations import InvestigationRepository
from app.repositories.relationships import RelationshipRepository
from app.services.progress import ProgressHub
from app.utils.ioc import InvalidIOCError, ParsedIOC, normalize_domain

log = logging.getLogger(__name__)

MAX_RELATED_PER_RUN = 300


class InvestigationCancelledError(Exception):
    pass


def normalize_asset_value(asset_type: str, value: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return None
    try:
        if asset_type in (AssetType.DOMAIN, AssetType.NAMESERVER):
            return normalize_domain(v)
        if asset_type == AssetType.IP:
            return str(ipaddress.ip_address(v.strip("[]")))
        if asset_type == AssetType.ASN:
            digits = v.upper().removeprefix("AS").strip()
            return f"AS{int(digits)}"
        if asset_type == AssetType.CERTIFICATE:
            return v.lower().replace(":", "")
    except (InvalidIOCError, ValueError):
        return None
    return v[:500]


@dataclass
class InvestigationContext:
    inv: Doc
    ioc: ParsedIOC
    options: InvestigationOptions
    db: AsyncIOMotorDatabase
    providers: ProviderManager
    assets: AssetRepository
    artifacts: ArtifactRepository
    relationships: RelationshipRepository
    investigations: InvestigationRepository
    hub: ProgressHub
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    root_asset: Doc | None = None
    state: dict[str, Any] = field(default_factory=dict)
    edge_count: int = 0

    @property
    def id(self) -> str:
        return str(self.inv["_id"])

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise InvestigationCancelledError()

    # ------------------------------------------------------------------ progress
    async def progress(self, stage: str, pct: int, message: str | None = None) -> None:
        pct = max(0, min(100, int(pct)))
        fields: dict[str, Any] = {"progress": pct}
        if message:
            fields["message"] = message
        await self.investigations.set_stage(self.id, stage, **fields)
        await self.hub.publish(
            self.id,
            {
                "type": "stage_progress",
                "investigation_id": self.id,
                "stage": stage,
                "progress": pct,
                "message": message,
                "timestamp": utcnow(),
            },
        )

    async def log(self, stage: str, message: str, level: str = "info") -> None:
        event = await self.investigations.push_event(self.id, stage, level, message)
        await self.hub.publish(self.id, {"type": "stage_event", "investigation_id": self.id, "stage": stage, **event})

    # ------------------------------------------------------------------ assets & edges
    async def add_asset(
        self,
        asset_type: AssetType | str,
        value: str,
        *,
        source: str,
        attributes: dict[str, Any] | None = None,
        fingerprints: dict[str, Any] | None = None,
        enrichment: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Doc | None:
        normalized = normalize_asset_value(str(asset_type), value)
        if normalized is None:
            return None
        return await self.assets.upsert(
            AssetType(str(asset_type)),
            normalized,
            investigation_id=self.id,
            source=source,
            attributes=attributes,
            fingerprints=fingerprints,
            enrichment=enrichment,
            extra=extra,
        )

    async def link(
        self,
        source: Doc | str,
        target: Doc | str,
        rel: RelationType | str,
        *,
        provider: str,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        sid = source if isinstance(source, str) else source["_id"]
        tid = target if isinstance(target, str) else target["_id"]
        if await self.relationships.upsert(
            sid, tid, str(rel), investigation_id=self.id, provider=provider, evidence=evidence
        ):
            self.edge_count += 1

    async def apply_related(self, origin: Doc, related: list[RelatedEntity], provider: str) -> int:
        count = 0
        for entity in related[:MAX_RELATED_PER_RUN]:
            try:
                asset_type = AssetType(entity.type)
            except ValueError:
                continue
            target = await self.add_asset(
                asset_type, entity.value, source=provider, attributes=entity.attributes or None
            )
            if target is None:
                continue
            if entity.reverse:
                await self.link(target, origin, entity.relation, provider=provider, evidence=entity.evidence)
            else:
                await self.link(origin, target, entity.relation, provider=provider, evidence=entity.evidence)
            count += 1
        return count

    async def record_provider_run(self, run: ProviderRun, asset: Doc | None, stage: str) -> None:
        entry = {**run.to_dict(), "stage": stage, "target": asset["value"] if asset else None, "at": utcnow()}
        await self.investigations.raw_update(self.id, {"$push": {"provider_runs": entry}})
        if asset is not None and run.ok:
            await self.assets.raw_update(
                asset["_id"],
                {
                    "$set": {f"enrichment.{run.provider}": {**run.result.summary, "_fetched_at": utcnow()}},
                    "$addToSet": {"sources": run.provider},
                },
            )
            if run.result.raw is not None and not run.cached:
                await self.artifacts.store_json(
                    f"provider:{run.provider}", run.result.raw, investigation_id=self.id, asset_id=asset["_id"]
                )
