"""Dashboard aggregation queries."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.mongo import Collections as C
from app.models.common import utcnow


async def build_dashboard(db: AsyncIOMotorDatabase) -> dict[str, Any]:
    now = utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=13)

    investigations_today = await db[C.INVESTIGATIONS].count_documents({"created_at": {"$gte": today}})
    running = await db[C.INVESTIGATIONS].count_documents({"status": {"$in": ["queued", "running"]}})
    assets_total = await db[C.ASSETS].count_documents({})
    assets_today = await db[C.ASSETS].count_documents({"first_seen": {"$gte": today}})
    clusters_total = await db[C.CLUSTERS].count_documents({})
    high_conf = await db[C.ASSETS].count_documents({"confidence": {"$gte": 70}})

    recent_investigations = (
        await db[C.INVESTIGATIONS]
        .find(
            {}, {"ioc": 1, "ioc_type": 1, "status": 1, "summary": 1, "created_at": 1, "created_by": 1, "finished_at": 1}
        )
        .sort("created_at", -1)
        .limit(10)
        .to_list(length=10)
    )
    recent_clusters = (
        await db[C.CLUSTERS]
        .find({}, {"name": 1, "confidence": 1, "confidence_level": 1, "counts": 1, "updated_at": 1, "severity": 1})
        .sort("updated_at", -1)
        .limit(8)
        .to_list(length=8)
    )
    recent_screens = (
        await db[C.ARTIFACTS]
        .find(
            {"kind": "screenshot_thumbnail"},
            {"file_id": 1, "asset_id": 1, "investigation_id": 1, "metadata": 1, "created_at": 1},
        )
        .sort("created_at", -1)
        .limit(12)
        .to_list(length=12)
    )
    screen_assets = {
        a["_id"]: a
        for a in await db[C.ASSETS]
        .find({"_id": {"$in": [s.get("asset_id") for s in recent_screens]}}, {"value": 1, "status": 1, "type": 1})
        .to_list(length=12)
    }

    by_type = {d["_id"]: d["n"] async for d in db[C.ASSETS].aggregate([{"$group": {"_id": "$type", "n": {"$sum": 1}}}])}
    by_status = {
        d["_id"]: d["n"]
        async for d in db[C.ASSETS].aggregate(
            [{"$match": {"type": {"$in": ["domain", "ip", "url"]}}}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}]
        )
    }
    timeline = [
        {"day": d["_id"], "investigations": d["n"]}
        async for d in db[C.INVESTIGATIONS].aggregate(
            [
                {"$match": {"created_at": {"$gte": week_ago}}},
                {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}}, "n": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ]
        )
    ]
    asset_timeline = {
        d["_id"]: d["n"]
        async for d in db[C.ASSETS].aggregate(
            [
                {"$match": {"first_seen": {"$gte": week_ago}}},
                {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$first_seen"}}, "n": {"$sum": 1}}},
            ]
        )
    }
    days = [(week_ago + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(14)]
    inv_by_day = {t["day"]: t["investigations"] for t in timeline}
    return {
        "stats": {
            "investigations_today": investigations_today,
            "investigations_running": running,
            "investigations_total": await db[C.INVESTIGATIONS].count_documents({}),
            "assets_discovered": assets_total,
            "assets_today": assets_today,
            "threat_clusters": clusters_total,
            "high_confidence_findings": high_conf,
            "relationships": await db[C.RELATIONSHIPS].estimated_document_count(),
        },
        "assets_by_type": by_type,
        "assets_by_status": by_status,
        "activity": [
            {"day": d, "investigations": inv_by_day.get(d, 0), "assets": asset_timeline.get(d, 0)} for d in days
        ],
        "recent_investigations": [{**i, "id": i.pop("_id")} for i in recent_investigations],
        "recent_clusters": [{**c, "id": c.pop("_id")} for c in recent_clusters],
        "recent_screenshots": [
            {
                "file_id": s["file_id"],
                "asset_id": s.get("asset_id"),
                "investigation_id": s.get("investigation_id"),
                "url": (s.get("metadata") or {}).get("final_url") or (s.get("metadata") or {}).get("url"),
                "value": screen_assets.get(s.get("asset_id"), {}).get("value"),
                "status": screen_assets.get(s.get("asset_id"), {}).get("status"),
                "created_at": s.get("created_at"),
            }
            for s in recent_screens
        ],
    }
