"""Certificate Transparency search via crt.sh."""

from __future__ import annotations

import html as html_lib
import re
from collections import Counter
from typing import Any

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, normalize_domain, registered_domain

MAX_CERTS = 300
_DNS_NAME_RE = re.compile(r"DNS:([A-Za-z0-9*._-]+)")
_CRTSH_ID_RE = re.compile(r"\?id=(\d+)")
MAX_RELATED = 400


def parse_crtsh(entries: list[dict[str, Any]], base_domain: str | None) -> tuple[dict[str, Any], list[RelatedEntity]]:
    entries = sorted(entries, key=lambda e: e.get("not_before") or "", reverse=True)[:MAX_CERTS]
    names: dict[str, dict[str, Any]] = {}
    issuers: Counter[str] = Counter()
    certs: list[dict[str, Any]] = []
    for e in entries:
        issuer = e.get("issuer_name") or ""
        issuers[_short_issuer(issuer)] += 1
        sans = sorted({n.strip().lower().lstrip("*.") for n in (e.get("name_value") or "").split("\n") if n.strip()})
        certs.append(
            {
                "crtsh_id": e.get("id"),
                "serial": e.get("serial_number"),
                "issuer": issuer,
                "common_name": e.get("common_name"),
                "not_before": e.get("not_before"),
                "not_after": e.get("not_after"),
                "san": sans[:50],
            }
        )
        for san in sans:
            if is_domain(san):
                names.setdefault(san, {"crtsh_ids": [], "issuer": _short_issuer(issuer)})
                if len(names[san]["crtsh_ids"]) < 5:
                    names[san]["crtsh_ids"].append(e.get("id"))

    related: list[RelatedEntity] = []
    for name, ev in list(names.items())[:MAX_RELATED]:
        if base_domain and name == base_domain:
            continue
        same_org = base_domain is not None and registered_domain(name) == base_domain
        related.append(
            RelatedEntity(
                type="domain",
                value=normalize_domain(name),
                relation=RelationType.SUBDOMAIN_OF if same_org else RelationType.SHARES_CERTIFICATE,
                reverse=same_org,
                evidence={"source": "crt.sh", **ev},
            )
        )
    summary = {
        "certificate_count": len(entries),
        "unique_names": len(names),
        "subdomains": sorted(n for n in names if base_domain and n.endswith("." + base_domain))[:200],
        "co_hosted_names": sorted(n for n in names if base_domain and registered_domain(n) != base_domain)[:200],
        "top_issuers": issuers.most_common(5),
        "first_seen": min((c["not_before"] for c in certs if c["not_before"]), default=None),
        "last_seen": max((c["not_before"] for c in certs if c["not_before"]), default=None),
        "recent_certificates": certs[:25],
    }
    return summary, related


def _short_issuer(issuer: str) -> str:
    for part in issuer.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip('"')
    return issuer[:80]


class CrtShProvider(BaseProvider):
    name = "crtsh"
    display_name = "crt.sh"
    description = "Certificate Transparency logs: certificates, SANs, subdomains and co-hosted names."
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.CERTIFICATE})
    supported_pivots = frozenset({"cert_sha256", "cert_sha1"})
    default_priority = 10
    default_cache_ttl_hours = 24
    docs_url = "https://crt.sh/"
    sample_ioc = "example.com"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        ctx.timeout = max(ctx.timeout, 45.0)  # crt.sh is notoriously slow
        if ioc.type == IOCType.CERTIFICATE:
            return await self._certificate(ioc.value, ctx, RelationType.USES_CERTIFICATE)
        base = registered_domain(ioc.host or ioc.value)
        entries = (
            await self.get_json(
                ctx, "https://crt.sh/", params={"q": f"%.{base}", "output": "json", "exclude": "expired"}, retries=2
            )
            or []
        )
        if not entries:
            entries = await self.get_json(ctx, "https://crt.sh/", params={"q": base, "output": "json"}, retries=2) or []
        summary, related = parse_crtsh(entries, base)
        return ProviderResult(summary=summary, related=related, raw={"count": len(entries)})

    async def _certificate(self, fingerprint: str, ctx: ProviderContext, relation: RelationType) -> ProviderResult:
        """Certificate pages are HTML only: extract the CT-logged SAN names and crt.sh id."""
        param = "sha256" if len(fingerprint) == 64 else "sha1"
        page = await self.get_text(ctx, "https://crt.sh/", params={param: fingerprint}, retries=2)
        names = sorted({html_lib.unescape(n).lower().lstrip("*.") for n in _DNS_NAME_RE.findall(page)})
        crt_id = _CRTSH_ID_RE.search(page)
        related = [
            RelatedEntity(
                type="domain",
                value=normalize_domain(n),
                relation=relation,
                reverse=True,
                evidence={"source": "crt.sh", "crtsh_id": crt_id.group(1) if crt_id else None},
            )
            for n in names
            if is_domain(n)
        ][:MAX_RELATED]
        summary = {"found": bool(names), "names": names[:200], "crtsh_id": crt_id.group(1) if crt_id else None}
        return ProviderResult(summary=summary, related=related, raw={"names": len(names)})

    async def pivot_search(self, kind: str, value: str, ctx: ProviderContext) -> ProviderResult:
        ctx.timeout = max(ctx.timeout, 45.0)
        return await self._certificate(value, ctx, RelationType.USES_CERTIFICATE)
