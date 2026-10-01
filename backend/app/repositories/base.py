"""Thin async repository base over a Motor collection."""

from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo import DESCENDING, ReturnDocument

from app.models.common import utcnow

Doc = dict[str, Any]


class Repository:
    collection_name: str = ""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.col: AsyncIOMotorCollection = db[self.collection_name]

    async def get(self, doc_id: str, projection: dict[str, Any] | None = None) -> Doc | None:
        return await self.col.find_one({"_id": doc_id}, projection)

    async def find_one(self, query: Doc, projection: dict[str, Any] | None = None) -> Doc | None:
        return await self.col.find_one(query, projection)

    async def find_page(
        self,
        query: Doc | None = None,
        *,
        sort: list[tuple[str, int]] | None = None,
        skip: int = 0,
        limit: int = 50,
        projection: dict[str, Any] | None = None,
    ) -> tuple[list[Doc], int]:
        query = query or {}
        cursor = self.col.find(query, projection).sort(sort or [("_id", DESCENDING)]).skip(skip).limit(limit)
        items = await cursor.to_list(length=limit)
        total = await self.col.count_documents(query)
        return items, total

    async def insert(self, doc: Doc) -> Doc:
        await self.col.insert_one(doc)
        return doc

    async def update(self, doc_id: str, fields: Doc, *, touch: bool = True) -> Doc | None:
        update_fields = dict(fields)
        if touch:
            update_fields.setdefault("updated_at", utcnow())
        return await self.col.find_one_and_update(
            {"_id": doc_id}, {"$set": update_fields}, return_document=ReturnDocument.AFTER
        )

    async def raw_update(self, doc_id: str, update: Doc) -> None:
        await self.col.update_one({"_id": doc_id}, update)

    async def delete(self, doc_id: str) -> bool:
        result = await self.col.delete_one({"_id": doc_id})
        return result.deleted_count == 1

    async def count(self, query: Doc | None = None) -> int:
        return await self.col.count_documents(query or {})


def paginate(page: int, page_size: int) -> tuple[int, int]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 500)
    return (page - 1) * page_size, page_size
