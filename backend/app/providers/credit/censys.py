"""Censys host / certificate lookups.

Supports both authentication styles:
* Censys Platform personal access token (api_key only) -> api.platform.censys.io v3
* Legacy Search API ID + secret (api_key + api_secret) -> search.censys.io v2
"""

from __future__ import annotations

import base64
from typing import Any

import aiohttp

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain

PLATFORM = "https://api.platform.censys.io/v3/global/asset"
LEGACY = "https://search.censys.io/api/v2"


def _service_cert(service: dict[str, Any]) -> str | None:
    tls = service.get("tls") or {}
    certs = tls.get("certificates")
    if isinstance(certs, dict) and certs.get("leaf_fp_sha_256"):
        return str(certs["leaf_fp_sha_256"])
    cert = service.get("cert")
    if isinstance(cert, dict):
        return cert.get("fingerprint_sha256")
    return None


class CensysProvider(BaseProvider):
    name = "censys"
    display_name = "Censys"
    description = "Host services, certificates and software on an IP; certificate names by SHA-256 (free tier)."
    category = "credit"
    supported_types = frozenset({IOCType.IP, IOCType.CERTIFICATE})
    requires_api_key = True
    accepts_api_key = True
    default_priority = 52
    default_cache_ttl_hours = 72
    default_daily_limit = 100
    docs_url = "https://docs.censys.com/"
    sample_ioc = "1.1.1.1"

    def _request_args(self, ctx: ProviderContext) -> tuple[str, dict[str, str], aiohttp.BasicAuth | None]:
        key = self.require_key(ctx)
        if ctx.api_secret:
            token = base64.b64encode(f"{key}:{ctx.api_secret}".encode()).decode()
            return LEGACY, {"Accept": "application/json", "Authorization": f"Basic {token}"}, None
        return (
            PLATFORM,
            {"Authorization": f"Bearer {key}", "Accept": "application/vnd.censys.api.v3.host.v1+json"},
            None,
        )

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        base, headers, auth = self._request_args(ctx)
        legacy = base == LEGACY
        if ioc.type == IOCType.CERTIFICATE:
            url = f"{base}/certificates/{ioc.value}" if legacy else f"{base}/certificate/{ioc.value}"
            payload = await self.get_json(ctx, url, headers=headers, auth=auth, allow_404=True)
            return self._parse_cert(payload, ioc.value)
        url = f"{base}/hosts/{ioc.value}" if legacy else f"{base}/host/{ioc.value}"
        payload = await self.get_json(ctx, url, headers=headers, auth=auth, allow_404=True)
        return self._parse_host(payload)

    def _parse_host(self, payload: dict[str, Any] | None) -> ProviderResult:
        if not payload:
            return ProviderResult(summary={"found": False}, credits_used=1)
        data = payload.get("result") or {}
        data = data.get("resource", data)
        services = data.get("services") or []
        asn = data.get("autonomous_system") or {}
        location = data.get("location") or {}
        names = sorted({n.lower() for n in (data.get("dns") or {}).get("names", []) if is_domain(n)})
        summary = {
            "found": True,
            "services": [
                {
                    "port": s.get("port"),
                    "protocol": s.get("service_name") or s.get("protocol"),
                    "transport": s.get("transport_protocol"),
                    "software": [sw.get("product") for sw in s.get("software") or [] if sw.get("product")],
                    "cert_sha256": _service_cert(s),
                }
                for s in services[:50]
            ],
            "asn": f"AS{asn['asn']}" if asn.get("asn") else None,
            "as_name": asn.get("name"),
            "country": location.get("country"),
            "dns_names": names[:100],
            "last_updated": data.get("last_updated_at"),
        }
        related: list[RelatedEntity] = [
            RelatedEntity(
                type="domain", value=n, relation=RelationType.RESOLVES_TO, reverse=True, evidence={"source": "censys"}
            )
            for n in names[:100]
        ]
        for svc in summary["services"]:
            if svc.get("cert_sha256"):
                related.append(
                    RelatedEntity(
                        type="certificate",
                        value=str(svc["cert_sha256"]).lower(),
                        relation=RelationType.USES_CERTIFICATE,
                        evidence={"source": "censys", "port": svc.get("port")},
                    )
                )
        return ProviderResult(summary=summary, related=related, credits_used=1)

    def _parse_cert(self, payload: dict[str, Any] | None, sha256: str) -> ProviderResult:
        if not payload:
            return ProviderResult(summary={"found": False}, credits_used=1)
        data = payload.get("result") or {}
        data = data.get("resource", data)
        parsed = data.get("parsed") or {}
        names = sorted({n.lower().lstrip("*.") for n in data.get("names") or [] if is_domain(n.lstrip("*."))})
        summary = {
            "found": True,
            "sha256": sha256,
            "issuer": parsed.get("issuer_dn"),
            "subject": parsed.get("subject_dn"),
            "validity": parsed.get("validity_period") or parsed.get("validity"),
            "names": names[:200],
        }
        related = [
            RelatedEntity(
                type="domain",
                value=n,
                relation=RelationType.USES_CERTIFICATE,
                reverse=True,
                evidence={"source": "censys"},
            )
            for n in names[:200]
        ]
        return ProviderResult(summary=summary, related=related, credits_used=1)
