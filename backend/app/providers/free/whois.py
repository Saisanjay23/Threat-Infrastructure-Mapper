"""Raw WHOIS (port 43) with IANA referral following."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderError, ProviderResult
from app.utils.ioc import ParsedIOC, is_domain, registered_domain

IANA_SERVER = "whois.iana.org"
_REFER_RE = re.compile(r"^(?:refer|whois|ReferralServer):\s*(?:whois://)?(\S+)", re.IGNORECASE | re.MULTILINE)

FIELD_PATTERNS: dict[str, list[str]] = {
    "registrar": [r"Registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)", r"registrar:\s*(.+)"],
    "created": [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)", r"Registration Time:\s*(.+)"],
    "expires": [
        r"Registry Expiry Date:\s*(.+)",
        r"Expiration Date:\s*(.+)",
        r"Expiry date:\s*(.+)",
        r"expires:\s*(.+)",
    ],
    "updated": [r"Updated Date:\s*(.+)", r"last-modified:\s*(.+)", r"changed:\s*(.+)"],
    "registrant_org": [r"Registrant Organi[sz]ation:\s*(.+)", r"org:\s*(.+)", r"OrgName:\s*(.+)"],
    "registrant_country": [r"Registrant Country:\s*(.+)", r"country:\s*(.+)", r"Country:\s*(.+)"],
    "abuse_email": [r"Registrar Abuse Contact Email:\s*(.+)", r"OrgAbuseEmail:\s*(.+)", r"abuse-mailbox:\s*(.+)"],
    "netname": [r"NetName:\s*(.+)", r"netname:\s*(.+)"],
    "cidr": [r"CIDR:\s*(.+)", r"inetnum:\s*(.+)", r"inet6num:\s*(.+)"],
}
_NS_RE = re.compile(r"^(?:Name Server|nserver|Nameservers?):\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^(?:Domain Status|status):\s*(\S+)", re.IGNORECASE | re.MULTILINE)


async def whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        raise ProviderError(f"whois: cannot connect to {server}: {exc}") from exc
    try:
        prefix = "n + " if server == "whois.arin.net" else ""
        writer.write(f"{prefix}{query}\r\n".encode())
        await writer.drain()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 512 * 1024:
                break
        return b"".join(chunks).decode("utf-8", errors="replace")
    except TimeoutError as exc:
        raise ProviderError(f"whois: timeout reading from {server}") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def parse_whois(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, patterns in FIELD_PATTERNS.items():
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                value = m.group(1).strip()
                if value and not value.lower().startswith(("redacted", "data protected")):
                    out[key] = value
                    break
    nameservers = sorted({m.lower().rstrip(".") for m in _NS_RE.findall(text)})
    if nameservers:
        out["nameservers"] = nameservers
    statuses = sorted(set(_STATUS_RE.findall(text)))
    if statuses:
        out["status"] = statuses
    out["privacy_protected"] = bool(re.search(r"privacy|redacted|withheld|proxy|whoisguard", text, re.IGNORECASE))
    return out


class WhoisProvider(BaseProvider):
    name = "whois"
    display_name = "WHOIS"
    description = "Port-43 WHOIS with IANA referral following for domains and IP addresses."
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL, IOCType.IP})
    default_priority = 3
    default_cache_ttl_hours = 72
    sample_ioc = "example.com"

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        host = ioc.host or ioc.value
        target = host if ioc.is_ip_host else registered_domain(host)
        timeout = min(ctx.timeout, 12.0)
        iana = await whois_query(IANA_SERVER, target, timeout)
        server_chain = [IANA_SERVER]
        text = iana
        refer = _REFER_RE.search(iana)
        for _ in range(2):
            if not refer:
                break
            server = refer.group(1).strip().split(":")[0]
            if server in server_chain:
                break
            server_chain.append(server)
            text = await whois_query(server, target, timeout)
            refer = _REFER_RE.search(text)
            if refer and refer.group(1).strip().split(":")[0] in server_chain:
                break
        summary = {"query": target, "servers": server_chain, **parse_whois(text)}
        related = [
            RelatedEntity(
                type="nameserver", value=ns, relation=RelationType.USES_NAMESERVER, evidence={"source": "whois"}
            )
            for ns in summary.get("nameservers", [])
            if is_domain(ns)
        ]
        return ProviderResult(summary=summary, related=related, raw={"text": text[:20000]})
