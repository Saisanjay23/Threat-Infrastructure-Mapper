"""RDAP registration data (rdap.org bootstrap)."""

from __future__ import annotations

from typing import Any

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, registered_domain


def _vcard_value(entity: dict[str, Any], field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            return str(value) if value else None
    return None


def _walk_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ent in entities or []:
        out.append(ent)
        out.extend(_walk_entities(ent.get("entities") or []))
    return out


def _events(data: dict[str, Any]) -> dict[str, str]:
    return {e.get("eventAction", ""): e.get("eventDate", "") for e in data.get("events") or [] if e.get("eventAction")}


def parse_entities(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for ent in _walk_entities(data.get("entities") or []):
        roles = ent.get("roles") or []
        name = _vcard_value(ent, "fn") or _vcard_value(ent, "org")
        email = _vcard_value(ent, "email")
        if "registrar" in roles and name:
            result["registrar"] = name
            for pid in ent.get("publicIds") or []:
                if pid.get("type", "").lower().startswith("iana"):
                    result["registrar_iana_id"] = pid.get("identifier")
        if "registrant" in roles:
            result["registrant"] = name
            result["registrant_org"] = _vcard_value(ent, "org") or name
        if "abuse" in roles and email:
            result["abuse_email"] = email
    return result


class RDAPProvider(BaseProvider):
    name = "rdap"
    display_name = "RDAP"
    description = "Registration Data Access Protocol lookups for domains and IP networks via rdap.org."
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.IP})
    default_priority = 2
    default_cache_ttl_hours = 72
    docs_url = "https://about.rdap.org/"
    sample_ioc = "example.com"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        host = ioc.host or ioc.value
        if ioc.is_ip_host:
            data = await self.get_json(ctx, f"https://rdap.org/ip/{host}", allow_404=True)
            if not data:
                return ProviderResult(summary={"found": False})
            summary = {
                "found": True,
                "network_name": data.get("name"),
                "handle": data.get("handle"),
                "start_address": data.get("startAddress"),
                "end_address": data.get("endAddress"),
                "cidr": [
                    f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs") or []
                ],
                "country": data.get("country"),
                "type": data.get("type"),
                **parse_entities(data),
                "events": _events(data),
            }
            return ProviderResult(summary=summary, raw=_trim(data))

        domain = registered_domain(host)
        data = await self.get_json(ctx, f"https://rdap.org/domain/{domain}", allow_404=True)
        if not data:
            return ProviderResult(summary={"found": False, "domain": domain})
        events = _events(data)
        nameservers = sorted(
            {(ns.get("ldhName") or "").lower().rstrip(".") for ns in data.get("nameservers") or []} - {""}
        )
        summary = {
            "found": True,
            "domain": domain,
            "handle": data.get("handle"),
            "status": data.get("status") or [],
            "created": events.get("registration"),
            "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "nameservers": nameservers,
            "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
            **parse_entities(data),
        }
        related = [
            RelatedEntity(
                type="nameserver", value=ns, relation=RelationType.USES_NAMESERVER, evidence={"source": "rdap"}
            )
            for ns in nameservers
            if is_domain(ns)
        ]
        return ProviderResult(summary=summary, related=related, raw=_trim(data))


def _trim(data: dict[str, Any]) -> dict[str, Any]:
    """Drop bulky notices/links to keep cached payloads small."""
    return {k: v for k, v in data.items() if k not in {"notices", "links", "remarks"}}
