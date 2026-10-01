"""Investigation repository with stage-state helpers."""

from __future__ import annotations

from typing import Any

from app.db.mongo import Collections
from app.models.common import utcnow
from app.models.investigation import STAGE_ORDER, StageStatus
from app.repositories.base import Doc, Repository

MAX_STAGE_EVENTS = 200


class InvestigationRepository(Repository):
    collection_name = Collections.INVESTIGATIONS

    @staticmethod
    def initial_stages() -> dict[str, Any]:
        return {
            s.value: {
                "status": StageStatus.PENDING.value,
                "progress": 0,
                "message": None,
                "started_at": None,
                "finished_at": None,
                "events": [],
            }
            for s in STAGE_ORDER
        }

    async def set_stage(self, inv_id: str, stage: str, **fields: Any) -> None:
        update = {f"stages.{stage}.{k}": v for k, v in fields.items()}
        update["updated_at"] = utcnow()
        await self.col.update_one({"_id": inv_id}, {"$set": update})

    async def push_event(self, inv_id: str, stage: str, level: str, message: str) -> dict[str, Any]:
        event = {"timestamp": utcnow(), "level": level, "message": message}
        await self.col.update_one(
            {"_id": inv_id},
            {
                "$push": {f"stages.{stage}.events": {"$each": [event], "$slice": -MAX_STAGE_EVENTS}},
                "$set": {"updated_at": utcnow()},
            },
        )
        return event

    async def add_note(self, inv_id: str, note: dict[str, Any]) -> Doc | None:
        await self.col.update_one({"_id": inv_id}, {"$push": {"notes": note}, "$set": {"updated_at": utcnow()}})
        return await self.get(inv_id)
