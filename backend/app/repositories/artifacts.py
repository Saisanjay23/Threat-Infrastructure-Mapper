"""Raw artifact storage: small payloads inline, binaries in GridFS."""

from __future__ import annotations

import hashlib
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from gridfs.errors import NoFile
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.db.mongo import Collections
from app.models.common import new_id, utcnow
from app.repositories.base import Doc, Repository


class ArtifactRepository(Repository):
    collection_name = Collections.ARTIFACTS

    def __init__(self, db: AsyncIOMotorDatabase, fs: AsyncIOMotorGridFSBucket) -> None:
        super().__init__(db)
        self.fs = fs

    async def store_json(
        self, kind: str, data: Any, *, investigation_id: str | None = None, asset_id: str | None = None
    ) -> Doc:
        doc = {
            "_id": new_id(),
            "investigation_id": investigation_id,
            "asset_id": asset_id,
            "kind": kind,
            "content_type": "application/json",
            "data": data,
            "created_at": utcnow(),
        }
        await self.col.insert_one(doc)
        return doc

    async def store_file(
        self,
        kind: str,
        content: bytes,
        *,
        filename: str,
        content_type: str,
        investigation_id: str | None = None,
        asset_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Doc:
        sha256 = hashlib.sha256(content).hexdigest()
        file_id = await self.fs.upload_from_stream(
            filename,
            content,
            metadata={"content_type": content_type, "kind": kind, "sha256": sha256, **(metadata or {})},
        )
        doc = {
            "_id": new_id(),
            "investigation_id": investigation_id,
            "asset_id": asset_id,
            "kind": kind,
            "content_type": content_type,
            "size": len(content),
            "sha256": sha256,
            "file_id": str(file_id),
            "filename": filename,
            "metadata": metadata or {},
            "created_at": utcnow(),
        }
        await self.col.insert_one(doc)
        return doc

    async def read_file(self, file_id: str) -> tuple[bytes, dict[str, Any]] | None:
        try:
            stream = await self.fs.open_download_stream(ObjectId(file_id))
        except (NoFile, InvalidId, ValueError, TypeError):
            return None
        data: bytes = await stream.read()
        return data, dict(stream.metadata or {})

    async def for_investigation(self, investigation_id: str, kinds: list[str] | None = None) -> list[Doc]:
        query: dict[str, Any] = {"investigation_id": investigation_id}
        if kinds:
            query["kind"] = {"$in": kinds}
        return await self.col.find(query).sort("created_at", 1).to_list(length=2000)

    async def for_asset(self, asset_id: str, kinds: list[str] | None = None, limit: int = 200) -> list[Doc]:
        query: dict[str, Any] = {"asset_id": asset_id}
        if kinds:
            query["kind"] = {"$in": kinds}
        return await self.col.find(query).sort("created_at", -1).limit(limit).to_list(length=limit)

    async def delete_for_investigation(self, investigation_id: str) -> int:
        docs = await self.col.find({"investigation_id": investigation_id}, {"file_id": 1}).to_list(length=None)
        for d in docs:
            if d.get("file_id"):
                try:
                    await self.fs.delete(ObjectId(d["file_id"]))
                except (NoFile, InvalidId):
                    pass
        result = await self.col.delete_many({"investigation_id": investigation_id})
        return result.deleted_count
