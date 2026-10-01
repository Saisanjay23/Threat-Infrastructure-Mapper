"""Index definitions for every collection. Idempotent; run at startup."""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

from app.db.mongo import Collections as C

INDEXES: dict[str, list[IndexModel]] = {
    C.USERS: [
        IndexModel([("username", ASCENDING)], unique=True),
        IndexModel([("email", ASCENDING)], unique=True, sparse=True),
    ],
    C.INVESTIGATIONS: [
        IndexModel([("created_at", DESCENDING)]),
        IndexModel([("status", ASCENDING)]),
        IndexModel([("ioc", ASCENDING)]),
        IndexModel([("created_by", ASCENDING)]),
        IndexModel([("bulk_id", ASCENDING)], sparse=True),
    ],
    C.ASSETS: [
        IndexModel([("type", ASCENDING), ("value", ASCENDING)], unique=True),
        IndexModel([("investigation_ids", ASCENDING)]),
        IndexModel([("last_seen", DESCENDING)]),
        IndexModel([("status", ASCENDING)]),
        IndexModel([("cluster_ids", ASCENDING)]),
        IndexModel([("fingerprints.favicon_mmh3", ASCENDING)], sparse=True),
        IndexModel([("fingerprints.cert_sha256", ASCENDING)], sparse=True),
        IndexModel([("fingerprints.tracking_ids", ASCENDING)], sparse=True),
        IndexModel([("fingerprints.title_hash", ASCENDING)], sparse=True),
        IndexModel([("value", "text"), ("attributes.title", "text")], name="asset_text"),
    ],
    C.ARTIFACTS: [
        IndexModel([("investigation_id", ASCENDING), ("kind", ASCENDING)]),
        IndexModel([("asset_id", ASCENDING)]),
        IndexModel([("created_at", DESCENDING)]),
    ],
    C.PROVIDERS: [IndexModel([("priority", ASCENDING)])],
    C.PROVIDER_CACHE: [
        IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0),
        IndexModel([("provider", ASCENDING)]),
    ],
    C.PROVIDER_USAGE: [IndexModel([("provider", ASCENDING), ("day", ASCENDING)], unique=True)],
    C.RELATIONSHIPS: [
        IndexModel([("source", ASCENDING), ("target", ASCENDING), ("type", ASCENDING)], unique=True),
        IndexModel([("target", ASCENDING)]),
        IndexModel([("investigation_ids", ASCENDING)]),
        IndexModel([("type", ASCENDING)]),
    ],
    C.CLUSTERS: [
        IndexModel([("updated_at", DESCENDING)]),
        IndexModel([("asset_ids", ASCENDING)]),
        IndexModel([("confidence", DESCENDING)]),
    ],
    C.CASES: [
        IndexModel([("updated_at", DESCENDING)]),
        IndexModel([("tags", ASCENDING)]),
        IndexModel([("asset_ids", ASCENDING)]),
        IndexModel([("status", ASCENDING)]),
    ],
    C.REPORTS: [IndexModel([("created_at", DESCENDING)]), IndexModel([("scope_id", ASCENDING)])],
    C.AUDIT_LOGS: [
        IndexModel([("timestamp", DESCENDING)]),
        IndexModel([("username", ASCENDING)]),
        IndexModel([("action", ASCENDING)]),
    ],
}


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    for collection, models in INDEXES.items():
        await db[collection].create_indexes(models)
