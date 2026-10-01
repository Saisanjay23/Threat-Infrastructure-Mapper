"""Team Cymru IP-to-ASN mapping over DNS."""

from __future__ import annotations

import ipaddress

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.providers.free.dns_provider import make_resolver, resolve
from app.utils.ioc import ParsedIOC


def origin_query_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_origin(txt: str) -> dict[str, str]:
    parts = [p.strip() for p in txt.strip('"').split("|")]
    keys = ["asn", "prefix", "country", "registry", "allocated"]
    return dict(zip(keys, parts, strict=False))


def parse_asname(txt: str) -> str | None:
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return parts[4] if len(parts) >= 5 else None


def hosting_name(as_name: str | None) -> str | None:
    """'CLOUDFLARENET - Cloudflare, Inc., US' -> 'Cloudflare, Inc.'"""
    if not as_name:
        return None
    name = as_name.split(" - ", 1)[1] if " - " in as_name else as_name
    if "," in name and len(name.rsplit(",", 1)[1].strip()) == 2:
        name = name.rsplit(",", 1)[0]
    return name.strip() or None


class TeamCymruProvider(BaseProvider):
    name = "cymru"
    display_name = "Team Cymru ASN"
    description = "Maps IP addresses to origin ASN, BGP prefix, country and AS organisation (hosting provider)."
    category = "free"
    supported_types = frozenset({IOCType.IP})
    default_priority = 4
    default_cache_ttl_hours = 168
    docs_url = "https://www.team-cymru.com/ip-asn-mapping"
    sample_ioc = "1.1.1.1"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        resolver = make_resolver(min(ctx.timeout, 8.0))
        answers = await resolve(resolver, origin_query_name(ioc.value), "TXT")
        if not answers:
            return ProviderResult(summary={"found": False})
        origin = parse_origin(answers[0])
        asn = origin.get("asn", "").split()[0] if origin.get("asn") else ""
        as_name = None
        if asn:
            names = await resolve(resolver, f"AS{asn}.asn.cymru.com", "TXT")
            as_name = parse_asname(names[0]) if names else None
        hosting = hosting_name(as_name)
        summary = {
            "found": bool(asn),
            "asn": f"AS{asn}" if asn else None,
            "prefix": origin.get("prefix"),
            "country": origin.get("country"),
            "registry": origin.get("registry"),
            "allocated": origin.get("allocated"),
            "as_name": as_name,
            "hosting_provider": hosting,
        }
        related: list[RelatedEntity] = []
        if asn:
            related.append(
                RelatedEntity(
                    type="asn",
                    value=f"AS{asn}",
                    relation=RelationType.BELONGS_TO_ASN,
                    evidence={"prefix": origin.get("prefix")},
                    attributes={"as_name": as_name, "country": origin.get("country")},
                )
            )
        if hosting:
            related.append(
                RelatedEntity(
                    type="hosting", value=hosting, relation=RelationType.HOSTED_ON, evidence={"asn": f"AS{asn}"}
                )
            )
        return ProviderResult(summary=summary, related=related, raw={"origin": answers, "as_name": as_name})
