"""AbuseIPDB reputation (free tier, API key required)."""

from __future__ import annotations

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain


class AbuseIPDBProvider(BaseProvider):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    description = "Community abuse reports and confidence score for IP addresses (free key, 1000 checks/day)."
    category = "free"
    supported_types = frozenset({IOCType.IP})
    requires_api_key = True
    accepts_api_key = True
    default_priority = 30
    default_cache_ttl_hours = 24
    default_daily_limit = 1000
    docs_url = "https://docs.abuseipdb.com/"
    sample_ioc = "1.1.1.1"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        key = self.require_key(ctx)
        payload = await self.get_json(
            ctx,
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": "90"},
        )
        data = (payload or {}).get("data") or {}
        hostnames: list[str] = list(data.get("hostnames") or [])
        summary = {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "distinct_users": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "country": data.get("countryCode"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
            "hostnames": hostnames,
        }
        related = [
            RelatedEntity(
                type="domain",
                value=h.lower(),
                relation=RelationType.RESOLVES_TO,
                reverse=True,
                evidence={"source": "abuseipdb", "record": "hostname"},
            )
            for h in hostnames
            if is_domain(h)
        ]
        return ProviderResult(summary=summary, related=related, raw=data)
