"""Persistence for the configurable correlation scoring model."""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.mongo import Collections
from app.models.common import utcnow
from app.models.scoring import ScoringConfig

SCORING_DOC_ID = "scoring"


async def get_scoring(db: AsyncIOMotorDatabase) -> ScoringConfig:
    doc = await db[Collections.SETTINGS].find_one({"_id": SCORING_DOC_ID})
    if not doc:
        return ScoringConfig()
    doc.pop("_id", None)
    doc.pop("updated_at", None)
    doc.pop("updated_by", None)
    return ScoringConfig.model_validate(doc)


async def save_scoring(db: AsyncIOMotorDatabase, config: ScoringConfig, username: str) -> ScoringConfig:
    await db[Collections.SETTINGS].replace_one(
        {"_id": SCORING_DOC_ID},
        {"_id": SCORING_DOC_ID, **config.model_dump(), "updated_at": utcnow(), "updated_by": username},
        upsert=True,
    )
    return config


async def reset_scoring(db: AsyncIOMotorDatabase) -> ScoringConfig:
    await db[Collections.SETTINGS].delete_one({"_id": SCORING_DOC_ID})
    return ScoringConfig()
