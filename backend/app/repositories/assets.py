"""Asset repository with idempotent upsert keyed on (type, value)."""

from __future__ import annotations

import hashlib
from typing import Any

from pymongo import ReturnDocument

from app.db.mongo import Collections
from app.models.common import AssetType, utcnow
from app.repositories.base import Doc, Repository


def asset_id(asset_type: AssetType | str, value: str) -> str:
    """Deterministic asset id so graph edges can be built without lookups."""
    return hashlib.sha256(f"{asset_type}|{value}".encode()).hexdigest()[:24]


def _flatten(prefix: str, data: dict[str, Any] | None) -> dict[str, Any]:
    return {f"{prefix}.{k}": v for k, v in (data or {}).items() if v is not None}


class AssetRepository(Repository):
    collection_name = Collections.ASSETS

    async def upsert(
        self,
        asset_type: AssetType | str,
        value: str,
        *,
        investigation_id: str | None = None,
        source: str | None = None,
        attributes: dict[str, Any] | None = None,
        fingerprints: dict[str, Any] | None = None,
        enrichment: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Doc:
        now = utcnow()
        aid = asset_id(asset_type, value)
        set_fields: dict[str, Any] = {"last_seen": now}
        set_fields.update(_flatten("attributes", attributes))
        set_fields.update(_flatten("fingerprints", fingerprints))
        set_fields.update(_flatten("enrichment", enrichment))
        if extra:
            set_fields.update({k: v for k, v in extra.items() if v is not None})
        add_to_set: dict[str, Any] = {}
        if investigation_id:
            add_to_set["investigation_ids"] = investigation_id
        if source:
            add_to_set["sources"] = source
        defaults = {"tags": [], "cluster_ids": [], "status": "UNKNOWN"}
        explicit = set(set_fields)
        update: dict[str, Any] = {
            "$setOnInsert": {
                "type": str(asset_type),
                "value": value,
                "first_seen": now,
                # Defaults only for fields the caller is not setting explicitly (avoids operator conflicts).
                **{k: v for k, v in defaults.items() if k not in explicit},
            },
            "$set": set_fields,
        }
        if add_to_set:
            update["$addToSet"] = add_to_set
        doc = await self.col.find_one_and_update(
            {"_id": aid}, update, upsert=True, return_document=ReturnDocument.AFTER
        )
        return doc

    async def by_investigation(self, investigation_id: str, limit: int = 5000) -> list[Doc]:
        cursor = self.col.find({"investigation_ids": investigation_id}).limit(limit)
        return await cursor.to_list(length=limit)

    async def find_by_fingerprint(
        self, field: str, value: Any, exclude_id: str | None = None, limit: int = 200
    ) -> list[Doc]:
        query: dict[str, Any] = {f"fingerprints.{field}": value}
        if exclude_id:
            query["_id"] = {"$ne": exclude_id}
        return await self.col.find(query).limit(limit).to_list(length=limit)
