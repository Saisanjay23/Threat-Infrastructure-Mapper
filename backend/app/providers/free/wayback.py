"""Internet Archive Wayback Machine CDX history."""

from __future__ import annotations

from typing import Any

from app.models.common import IOCType
from app.providers.base import BaseProvider, ProviderContext, ProviderError, ProviderResult
from app.utils.ioc import ParsedIOC


def _fmt(ts: str) -> str:
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z" if len(ts) >= 14 else ts


class WaybackProvider(BaseProvider):
    name = "wayback"
    display_name = "Wayback Machine"
    description = "Historical captures from the Internet Archive (first/last seen, monthly snapshots)."
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL})
    default_priority = 20
    default_cache_ttl_hours = 72
    docs_url = "https://archive.org/help/wayback_api.php"
    sample_ioc = "example.com"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        ctx.timeout = max(ctx.timeout, 30.0)
        target = (ioc.host if ioc.type == IOCType.DOMAIN else ioc.value) or ioc.value
        try:
            rows: list[list[str]] = (
                await self.get_json(
                    ctx,
                    "https://web.archive.org/cdx/search/cdx",
                    params={
                        "url": target,
                        "output": "json",
                        "fl": "timestamp,original,statuscode,mimetype,digest",
                        "collapse": "timestamp:6",
                        "filter": "mimetype:text/html",
                        "limit": "500",
                    },
                    retries=0,
                )
                or []
            )
        except (TimeoutError, ProviderError):
            return await self._availability(target, ctx)
        if rows and rows[0] and rows[0][0] == "timestamp":
            rows = rows[1:]
        snapshots: list[dict[str, Any]] = [
            {
                "timestamp": _fmt(r[0]),
                "original": r[1],
                "status": r[2],
                "digest": r[4] if len(r) > 4 else None,
                "archive_url": f"https://web.archive.org/web/{r[0]}/{r[1]}",
                "screenshot_url": f"https://web.archive.org/web/{r[0]}im_/{r[1]}",
            }
            for r in rows
            if len(r) >= 3
        ]
        distinct_digests = len({s["digest"] for s in snapshots if s.get("digest")})
        summary = {
            "snapshot_count": len(snapshots),
            "first_seen": snapshots[0]["timestamp"] if snapshots else None,
            "last_seen": snapshots[-1]["timestamp"] if snapshots else None,
            "distinct_content_versions": distinct_digests,
            "recent_snapshots": snapshots[-24:][::-1],
        }
        return ProviderResult(summary=summary, raw={"rows": len(rows)})

    async def _availability(self, target: str, ctx: ProviderContext) -> ProviderResult:
        """Fast fallback when the CDX index is slow: closest snapshot only."""
        ctx.timeout = 20.0
        data = await self.get_json(ctx, "https://archive.org/wayback/available", params={"url": target}) or {}
        closest = (data.get("archived_snapshots") or {}).get("closest") or {}
        ts = closest.get("timestamp", "")
        snapshot = (
            {
                "timestamp": _fmt(ts),
                "original": target,
                "status": closest.get("status"),
                "digest": None,
                "archive_url": closest.get("url"),
                "screenshot_url": f"https://web.archive.org/web/{ts}im_/{target}",
            }
            if closest
            else None
        )
        summary = {
            "snapshot_count": 1 if snapshot else 0,
            "first_seen": None,
            "last_seen": snapshot["timestamp"] if snapshot else None,
            "distinct_content_versions": None,
            "recent_snapshots": [snapshot] if snapshot else [],
            "partial": True,
        }
        return ProviderResult(summary=summary, raw=data)
