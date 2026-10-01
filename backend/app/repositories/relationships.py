"""Graph edge persistence (asset -> asset relationships)."""

from __future__ import annotations

import hashlib
from typing import Any

from app.db.mongo import Collections
from app.models.common import utcnow
from app.repositories.base import Doc, Repository


def edge_id(source: str, target: str, rel_type: str) -> str:
    return hashlib.sha256(f"{source}|{rel_type}|{target}".encode()).hexdigest()[:24]


class RelationshipRepository(Repository):
    collection_name = Collections.RELATIONSHIPS

    async def upsert(
        self,
        source: str,
        target: str,
        rel_type: str,
        *,
        investigation_id: str | None = None,
        provider: str | None = None,
        evidence: dict[str, Any] | None = None,
        weight: float | None = None,
    ) -> str | None:
        if source == target:
            return None
        now = utcnow()
        eid = edge_id(source, target, rel_type)
        update: dict[str, Any] = {
            "$setOnInsert": {"source": source, "target": target, "type": rel_type, "first_seen": now},
            "$set": {"last_seen": now},
        }
        add: dict[str, Any] = {}
        if investigation_id:
            add["investigation_ids"] = investigation_id
        if provider:
            add["sources"] = provider
        if add:
            update["$addToSet"] = add
        if evidence:
            update["$push"] = {"evidence": {"$each": [{**evidence, "observed_at": now}], "$slice": -20}}
        if weight is not None:
            update["$set"]["weight"] = weight
        else:
            update["$setOnInsert"]["weight"] = 1.0
        await self.col.update_one({"_id": eid}, update, upsert=True)
        return eid

    async def for_assets(self, asset_ids: list[str], limit: int = 20000) -> list[Doc]:
        cursor = self.col.find({"$or": [{"source": {"$in": asset_ids}}, {"target": {"$in": asset_ids}}]}).limit(limit)
        return await cursor.to_list(length=limit)

    async def for_investigation(self, investigation_id: str, limit: int = 20000) -> list[Doc]:
        cursor = self.col.find({"investigation_ids": investigation_id}).limit(limit)
        return await cursor.to_list(length=limit)
