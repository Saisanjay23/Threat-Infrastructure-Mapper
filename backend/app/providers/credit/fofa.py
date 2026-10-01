"""FOFA search engine (free tier key)."""

from __future__ import annotations

import base64
from typing import Any

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderError, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, is_ip

# FOFA restricts which result fields an account tier may request (error 820001). TIM asks for the
# richest set first and steps down until the account accepts it; the working tier is remembered.
FIELD_TIERS: list[list[str]] = [
    ["host", "ip", "port", "domain", "title", "server", "country", "as_number", "as_organization", "lastupdatetime"],
    ["host", "ip", "port", "domain", "title", "server", "country"],
    ["host", "ip", "port", "domain", "title"],
    ["host", "ip", "port"],
]
FIELDS = FIELD_TIERS[0]
FIELD_PERMISSION_ERROR = "820001"
ERROR_HINTS = {
    "820001": "your FOFA membership level cannot use this query field or keyword",
    "820031": "not enough F-points left on the FOFA account",
    "820000": "FOFA query syntax error",
    "-700": "invalid FOFA API key",
    "45022": "invalid FOFA API key",
    "45011": "FOFA rate limit reached",
}


def _error_message(errmsg: str) -> str:
    for code, hint in ERROR_HINTS.items():
        if f"[{code}]" in errmsg or errmsg.strip().startswith(code):
            return f"fofa: {hint} ({errmsg})"
    return f"fofa: {errmsg}"


def _q(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


class FofaProvider(BaseProvider):
    name = "fofa"
    display_name = "FOFA"
    description = "Cyberspace search engine; pivots on favicon hash, certificate, title, IP and domain."
    category = "credit"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.IP, IOCType.CERTIFICATE})
    supported_pivots = frozenset({"favicon_mmh3", "cert_sha1", "title", "ip", "domain", "tracking_id"})
    requires_api_key = True
    accepts_api_key = True
    default_priority = 53
    default_cache_ttl_hours = 48
    default_daily_limit = 100
    docs_url = "https://en.fofa.info/api"
    sample_ioc = "example.com"

    _tier: int = 0  # index into FIELD_TIERS that this process found to work

    async def _request(self, query: str, ctx: ProviderContext, fields: list[str]) -> dict[str, Any]:
        params: dict[str, Any] = {
            "key": self.require_key(ctx),
            "qbase64": base64.b64encode(query.encode()).decode(),
            "fields": ",".join(fields),
            "size": "100",
        }
        if ctx.api_secret:
            params["email"] = ctx.api_secret
        payload = await self.get_json(ctx, "https://fofa.info/api/v1/search/all", params=params)
        return payload or {}

    async def _search(self, query: str, ctx: ProviderContext, relation: RelationType) -> ProviderResult:
        tier = FofaProvider._tier
        while True:
            fields = FIELD_TIERS[tier]
            payload = await self._request(query, ctx, fields)
            errmsg = str(payload.get("errmsg") or "")
            if payload.get("error") and FIELD_PERMISSION_ERROR in errmsg and tier + 1 < len(FIELD_TIERS):
                tier += 1  # account cannot request some fields: retry with a smaller field set
                continue
            if payload.get("error"):
                raise ProviderError(_error_message(errmsg or "unknown error"))
            FofaProvider._tier = tier
            break
        rows = [dict(zip(fields, r, strict=False)) for r in payload.get("results") or []]
        related: dict[tuple[str, str], RelatedEntity] = {}
        for row in rows:
            domain = (row.get("domain") or "").lower()
            host = (row.get("host") or "").split("://")[-1].split(":")[0].lower()
            for candidate in {domain, host}:
                if candidate and is_domain(candidate):
                    related.setdefault(
                        ("domain", candidate),
                        RelatedEntity(
                            type="domain",
                            value=candidate,
                            relation=relation,
                            evidence={"source": "fofa", "query": query, "port": row.get("port")},
                            attributes={"title": row.get("title")},
                        ),
                    )
            ip = row.get("ip") or ""
            if is_ip(ip):
                related.setdefault(
                    ("ip", ip),
                    RelatedEntity(
                        type="ip",
                        value=ip,
                        relation=relation,
                        evidence={"source": "fofa", "query": query, "port": row.get("port")},
                        attributes={"asn": row.get("as_number"), "as_org": row.get("as_organization")},
                    ),
                )
        summary = {
            "query": query,
            "fields": fields,
            "total": payload.get("size"),
            "results": rows[:50],
            "distinct_ips": sorted({r["ip"] for r in rows if r.get("ip")})[:100],
            "titles": sorted({r["title"] for r in rows if r.get("title")})[:30],
        }
        return ProviderResult(summary=summary, related=list(related.values()), credits_used=1)

    async def account_info(self, ctx: ProviderContext) -> dict[str, Any] | None:
        info = await self.get_json(ctx, "https://fofa.info/api/v1/info/my", params={"key": self.require_key(ctx)})
        if not info or info.get("error"):
            raise ProviderError(_error_message(str((info or {}).get("errmsg") or "account lookup failed")))
        out = {
            k: info.get(k)
            for k in (
                "isvip",
                "vip_level",
                "fofa_point",
                "remain_free_point",
                "remain_api_query",
                "remain_api_data",
                "is_verified",
            )
        }
        no_quota = not info.get("isvip") and not info.get("fofa_point") and not info.get("remain_api_query")
        out["api_search_available"] = not no_quota
        if no_quota:
            out["advice"] = (
                "Key is valid, but the account has no API search allowance (non-VIP, 0 F-points, "
                "0 remaining API queries). Verify the account, add F-points or upgrade membership on fofa.info."
            )
        return out

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        if ioc.type == IOCType.IP:
            return await self._search(f"ip={_q(ioc.value)}", ctx, RelationType.RESOLVES_TO)
        if ioc.type == IOCType.CERTIFICATE:
            return await self._search(f"cert={_q(ioc.value)}", ctx, RelationType.USES_CERTIFICATE)
        return await self._search(f"domain={_q(ioc.host or ioc.value)}", ctx, RelationType.OBSERVED_WITH)

    async def pivot_search(self, kind: str, value: str, ctx: ProviderContext) -> ProviderResult:
        queries = {
            "favicon_mmh3": (f"icon_hash={_q(value)}", RelationType.SHARES_FAVICON),
            "cert_sha1": (f"cert={_q(value)}", RelationType.USES_CERTIFICATE),
            "title": (f"title={_q(value)}", RelationType.SIMILAR_TITLE),
            "ip": (f"ip={_q(value)}", RelationType.RESOLVES_TO),
            "domain": (f"domain={_q(value)}", RelationType.OBSERVED_WITH),
            "tracking_id": (f"body={_q(value)}", RelationType.SHARES_TRACKING),
        }
        if kind not in queries:
            return await super().pivot_search(kind, value, ctx)
        q, relation = queries[kind]
        return await self._search(q, ctx, relation)
