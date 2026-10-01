"""urlscan.io search API (free tier)."""

from __future__ import annotations

from typing import Any

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, is_ip

SEARCH = "https://urlscan.io/api/v1/search/"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_results(results: list[dict[str, Any]], relation: RelationType) -> tuple[dict[str, Any], list[RelatedEntity]]:
    scans: list[dict[str, Any]] = []
    related: dict[tuple[str, str], RelatedEntity] = {}
    for r in results:
        page = r.get("page") or {}
        task = r.get("task") or {}
        scan = {
            "uuid": r.get("_id"),
            "time": task.get("time"),
            "url": page.get("url") or task.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "server": page.get("server"),
            "title": page.get("title"),
            "status": page.get("status"),
            "country": page.get("country"),
            "screenshot": r.get("screenshot"),
            "result": r.get("result"),
        }
        scans.append(scan)
        domain = (page.get("domain") or "").lower()
        if domain and is_domain(domain):
            related.setdefault(
                ("domain", domain),
                RelatedEntity(
                    type="domain",
                    value=domain,
                    relation=relation,
                    evidence={"source": "urlscan", "scan": scan["uuid"], "time": scan["time"]},
                    attributes={"title": scan["title"]},
                ),
            )
        ip = page.get("ip") or ""
        if ip and is_ip(ip):
            related.setdefault(
                ("ip", ip),
                RelatedEntity(
                    type="ip",
                    value=ip,
                    relation=RelationType.HISTORICAL_RESOLUTION,
                    evidence={"source": "urlscan", "scan": scan["uuid"], "time": scan["time"]},
                ),
            )
    summary = {
        "scan_count": len(scans),
        "first_scan": min((s["time"] for s in scans if s["time"]), default=None),
        "last_scan": max((s["time"] for s in scans if s["time"]), default=None),
        "distinct_ips": sorted({s["ip"] for s in scans if s["ip"]}),
        "distinct_asns": sorted({s["asn"] for s in scans if s["asn"]}),
        "titles": sorted({s["title"] for s in scans if s["title"]})[:20],
        "historical_screenshots": [
            {"time": s["time"], "url": s["url"], "screenshot": s["screenshot"]} for s in scans if s["screenshot"]
        ][:30],
        "recent_scans": scans[:25],
    }
    return summary, list(related.values())


class UrlscanProvider(BaseProvider):
    name = "urlscan"
    display_name = "urlscan.io"
    description = "Historical scans: IPs, ASNs, page titles and screenshots; supports favicon/title/IP pivots."
    category = "credit"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.IP})
    supported_pivots = frozenset({"favicon_sha256", "title", "ip", "domain", "asn"})
    accepts_api_key = True
    default_priority = 51
    default_cache_ttl_hours = 24
    default_daily_limit = 1000
    docs_url = "https://urlscan.io/docs/api/"
    sample_ioc = "example.com"

    def _headers(self, ctx: ProviderContext) -> dict[str, str]:
        return {"API-Key": ctx.api_key} if ctx.api_key else {}

    async def _search(self, q: str, ctx: ProviderContext, relation: RelationType) -> ProviderResult:
        payload = await self.get_json(ctx, SEARCH, headers=self._headers(ctx), params={"q": q, "size": "100"})
        summary, related = parse_results((payload or {}).get("results") or [], relation)
        summary["query"] = q
        summary["total"] = (payload or {}).get("total")
        return ProviderResult(summary=summary, related=related, credits_used=1)

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        if ioc.type == IOCType.IP:
            return await self._search(f"ip:{_quote(ioc.value)}", ctx, RelationType.RESOLVES_TO)
        host = ioc.host or ioc.value
        return await self._search(f"domain:{_quote(host)}", ctx, RelationType.OBSERVED_WITH)

    async def pivot_search(self, kind: str, value: str, ctx: ProviderContext) -> ProviderResult:
        queries = {
            "favicon_sha256": (f"hash:{value}", RelationType.SHARES_FAVICON),
            "title": (f"page.title:{_quote(value)}", RelationType.SIMILAR_TITLE),
            "ip": (f"ip:{_quote(value)}", RelationType.RESOLVES_TO),
            "domain": (f"domain:{_quote(value)}", RelationType.OBSERVED_WITH),
            "asn": (f"page.asn:{_quote(value)}", RelationType.BELONGS_TO_ASN),
        }
        if kind not in queries:
            return await super().pivot_search(kind, value, ctx)
        q, relation = queries[kind]
        return await self._search(q, ctx, relation)
