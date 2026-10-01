"""VirusTotal v3 public API."""

from __future__ import annotations

import base64
from typing import Any

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, is_ip

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(BaseProvider):
    name = "virustotal"
    display_name = "VirusTotal"
    description = "Detection stats, reputation, categories, HTTPS certificate and DNS records (public API 500/day)."
    category = "credit"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.IP, IOCType.CERTIFICATE})
    requires_api_key = True
    accepts_api_key = True
    default_priority = 50
    default_cache_ttl_hours = 48
    default_daily_limit = 500
    docs_url = "https://docs.virustotal.com/reference/overview"
    sample_ioc = "example.com"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        key = self.require_key(ctx)
        headers = {"x-apikey": key, "Accept": "application/json"}
        if ioc.type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            endpoint = f"{BASE}/urls/{url_id}"
        elif ioc.type == IOCType.IP:
            endpoint = f"{BASE}/ip_addresses/{ioc.value}"
        elif ioc.type == IOCType.CERTIFICATE:
            return await self._certificate_search(ioc.value, ctx, headers)
        else:
            endpoint = f"{BASE}/domains/{ioc.value}"
        payload = await self.get_json(ctx, endpoint, headers=headers, allow_404=True)
        if not payload:
            return ProviderResult(summary={"found": False}, credits_used=1)
        attrs: dict[str, Any] = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        cert = attrs.get("last_https_certificate") or {}
        summary = {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories") or {},
            "tags": attrs.get("tags") or [],
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "jarm": attrs.get("jarm"),
            "as_owner": attrs.get("as_owner"),
            "asn": attrs.get("asn"),
            "country": attrs.get("country"),
            "title": attrs.get("title"),
            "cert_thumbprint_sha256": cert.get("thumbprint_sha256"),
            "cert_issuer": (cert.get("issuer") or {}).get("O"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
        related: list[RelatedEntity] = []
        for rec in attrs.get("last_dns_records") or []:
            value = str(rec.get("value", "")).rstrip(".").lower()
            if rec.get("type") in ("A", "AAAA") and is_ip(value):
                related.append(
                    RelatedEntity(
                        type="ip",
                        value=value,
                        relation=RelationType.RESOLVES_TO,
                        evidence={"source": "virustotal", "record": rec.get("type")},
                    )
                )
            elif rec.get("type") == "NS" and is_domain(value):
                related.append(
                    RelatedEntity(
                        type="nameserver",
                        value=value,
                        relation=RelationType.USES_NAMESERVER,
                        evidence={"source": "virustotal"},
                    )
                )
        if cert.get("thumbprint_sha256"):
            related.append(
                RelatedEntity(
                    type="certificate",
                    value=cert["thumbprint_sha256"].lower(),
                    relation=RelationType.USES_CERTIFICATE,
                    evidence={"source": "virustotal"},
                    attributes={"issuer": summary["cert_issuer"]},
                )
            )
        return ProviderResult(summary=summary, related=related, raw={"attributes": _trim(attrs)}, credits_used=1)

    async def _certificate_search(self, sha256: str, ctx: ProviderContext, headers: dict[str, str]) -> ProviderResult:
        payload = await self.get_json(
            ctx,
            f"{BASE}/intelligence/search",
            headers=headers,
            params={"query": f"entity:domain ssl_certificate:{sha256}"},
            allow_404=True,
        )
        related = [
            RelatedEntity(
                type="domain",
                value=d["id"],
                relation=RelationType.USES_CERTIFICATE,
                reverse=True,
                evidence={"source": "virustotal"},
            )
            for d in (payload or {}).get("data") or []
            if is_domain(d.get("id", ""))
        ]
        return ProviderResult(summary={"domains": len(related)}, related=related, credits_used=1)


def _trim(attrs: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in attrs.items() if k not in {"last_analysis_results", "popularity_ranks"}}
