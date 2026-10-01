"""MongoDB (Motor) connection lifecycle and GridFS access."""

from __future__ import annotations

import logging

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import get_settings

log = logging.getLogger(__name__)


class Collections:
    USERS = "users"
    INVESTIGATIONS = "investigations"
    ASSETS = "assets"
    ARTIFACTS = "artifacts"
    PROVIDERS = "providers"
    PROVIDER_CACHE = "provider_cache"
    PROVIDER_USAGE = "provider_usage"
    RELATIONSHIPS = "relationships"
    CLUSTERS = "clusters"
    CASES = "cases"
    SETTINGS = "settings"
    AUDIT_LOGS = "audit_logs"
    REPORTS = "reports"


class Mongo:
    """Holds the process-wide Motor client. Connect once at startup."""

    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None
    fs: AsyncIOMotorGridFSBucket | None = None

    @classmethod
    async def connect(cls, uri: str | None = None, db_name: str | None = None) -> AsyncIOMotorDatabase:
        settings = get_settings()
        cls.client = AsyncIOMotorClient(
            uri or settings.mongo_uri,
            serverSelectionTimeoutMS=5000,
            uuidRepresentation="standard",
            tz_aware=True,
        )
        cls.db = cls.client[db_name or settings.mongo_db]
        cls.fs = AsyncIOMotorGridFSBucket(cls.db, bucket_name="files")
        await cls.client.admin.command("ping")
        log.info("Connected to MongoDB database '%s'", cls.db.name)
        from app.db.indexes import ensure_indexes

        await ensure_indexes(cls.db)
        return cls.db

    @classmethod
    async def close(cls) -> None:
        if cls.client is not None:
            cls.client.close()
        cls.client = cls.db = cls.fs = None

    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        if cls.db is None:
            raise RuntimeError("MongoDB is not connected")
        return cls.db

    @classmethod
    def get_fs(cls) -> AsyncIOMotorGridFSBucket:
        if cls.fs is None:
            raise RuntimeError("MongoDB GridFS is not initialised")
        return cls.fs


def get_db() -> AsyncIOMotorDatabase:
    return Mongo.get_db()


def get_fs() -> AsyncIOMotorGridFSBucket:
    return Mongo.get_fs()
