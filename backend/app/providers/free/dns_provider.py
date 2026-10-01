"""Live DNS resolution (dnspython)."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, normalize_domain

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def make_resolver(timeout: float = 5.0) -> dns.asyncresolver.Resolver:
    try:
        resolver = dns.asyncresolver.Resolver()
        if not resolver.nameservers:
            raise dns.resolver.NoResolverConfiguration
    except (dns.resolver.NoResolverConfiguration, OSError):
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = FALLBACK_NAMESERVERS
    resolver.lifetime = timeout
    resolver.timeout = timeout / 2
    return resolver


async def resolve(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return []
    if answer.rrset is None:
        return []
    return [r.to_text() for r in answer.rrset]


class DNSProvider(BaseProvider):
    name = "dns"
    display_name = "Live DNS"
    description = "Resolves A, AAAA, CNAME, MX, NS, TXT, SOA and CAA records, and PTR for IP addresses."
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.IP})
    default_priority = 1
    default_cache_ttl_hours = 1
    sample_ioc = "example.com"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        resolver = make_resolver(min(ctx.timeout, 8.0))
        host = ioc.host or ioc.value
        if ioc.is_ip_host:
            ptr_name = dns.reversename.from_address(host).to_text()
            ptrs = [p.rstrip(".").lower() for p in await resolve(resolver, ptr_name, "PTR")]
            ptr_related = [
                RelatedEntity(
                    type="domain", value=p, relation=RelationType.RESOLVES_TO, reverse=True, evidence={"record": "PTR"}
                )
                for p in ptrs
                if is_domain(p)
            ]
            return ProviderResult(summary={"ptr": ptrs}, related=ptr_related, raw={"PTR": ptrs})

        results = await asyncio.gather(*(resolve(resolver, host, rt) for rt in RECORD_TYPES))
        records: dict[str, list[str]] = dict(zip(RECORD_TYPES, results, strict=True))
        related: list[RelatedEntity] = []
        for ip in records["A"] + records["AAAA"]:
            related.append(
                RelatedEntity(
                    type="ip",
                    value=ip,
                    relation=RelationType.RESOLVES_TO,
                    evidence={"record": "A" if ":" not in ip else "AAAA"},
                )
            )
        nameservers = sorted({ns.rstrip(".").lower() for ns in records["NS"]})
        for ns in nameservers:
            related.append(
                RelatedEntity(
                    type="nameserver", value=ns, relation=RelationType.USES_NAMESERVER, evidence={"record": "NS"}
                )
            )
        mx_hosts: list[str] = []
        for mx in records["MX"]:
            parts = mx.split()
            if len(parts) == 2:
                mx_host = parts[1].rstrip(".").lower()
                if mx_host and is_domain(mx_host):
                    mx_hosts.append(mx_host)
                    related.append(
                        RelatedEntity(
                            type="domain",
                            value=normalize_domain(mx_host),
                            relation=RelationType.USES_MX,
                            evidence={"record": "MX", "preference": parts[0]},
                        )
                    )
        for cname in records["CNAME"]:
            target = cname.rstrip(".").lower()
            if is_domain(target):
                related.append(
                    RelatedEntity(
                        type="domain",
                        value=normalize_domain(target),
                        relation=RelationType.CNAME_TO,
                        evidence={"record": "CNAME"},
                    )
                )

        txt = [t.strip('"') for t in records["TXT"]]
        summary: dict[str, Any] = {
            "a": records["A"],
            "aaaa": records["AAAA"],
            "cname": [c.rstrip(".") for c in records["CNAME"]],
            "mx": mx_hosts,
            "ns": nameservers,
            "txt": txt,
            "soa": records["SOA"][0] if records["SOA"] else None,
            "caa": records["CAA"],
            "spf": next((t for t in txt if t.lower().startswith("v=spf1")), None),
            "resolves": bool(records["A"] or records["AAAA"] or records["CNAME"]),
        }
        return ProviderResult(summary=summary, related=related, raw=records)
