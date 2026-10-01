"""GreyNoise Community API (key optional)."""

from __future__ import annotations

import ipaddress

from app.models.common import IOCType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC


class GreyNoiseProvider(BaseProvider):
    name = "greynoise"
    display_name = "GreyNoise Community"
    description = "Whether an IP is internet background noise or a known benign service (RIOT)."
    category = "free"
    supported_types = frozenset({IOCType.IP})
    accepts_api_key = True
    default_priority = 31
    default_cache_ttl_hours = 24
    default_daily_limit = 50
    docs_url = "https://docs.greynoise.io/reference/get_v3-community-ip"
    sample_ioc = "8.8.8.8"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        if ipaddress.ip_address(ioc.value).version != 4:
            return ProviderResult(summary={"seen": False, "note": "GreyNoise Community covers IPv4 only"})
        headers = {"Accept": "application/json"}
        if ctx.api_key:
            headers["key"] = ctx.api_key
        data = await self.get_json(
            ctx, f"https://api.greynoise.io/v3/community/{ioc.value}", headers=headers, allow_404=True
        )
        if data is None:
            return ProviderResult(summary={"seen": False, "noise": False, "riot": False})
        summary = {
            "seen": bool(data.get("noise") or data.get("riot")),
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "link": data.get("link"),
            "message": data.get("message"),
        }
        return ProviderResult(summary=summary, raw=data)
