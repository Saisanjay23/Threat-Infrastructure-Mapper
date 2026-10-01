"""Static registry of all provider implementations."""

from __future__ import annotations

from app.providers.base import BaseProvider
from app.providers.credit.censys import CensysProvider
from app.providers.credit.fofa import FofaProvider
from app.providers.credit.urlscan import UrlscanProvider
from app.providers.credit.virustotal import VirusTotalProvider
from app.providers.free.abuseipdb import AbuseIPDBProvider
from app.providers.free.crtsh import CrtShProvider
from app.providers.free.cymru import TeamCymruProvider
from app.providers.free.dns_provider import DNSProvider
from app.providers.free.greynoise import GreyNoiseProvider
from app.providers.free.rdap import RDAPProvider
from app.providers.free.wayback import WaybackProvider
from app.providers.free.whois import WhoisProvider

PROVIDER_CLASSES: list[type[BaseProvider]] = [
    DNSProvider,
    RDAPProvider,
    WhoisProvider,
    TeamCymruProvider,
    CrtShProvider,
    WaybackProvider,
    AbuseIPDBProvider,
    GreyNoiseProvider,
    VirusTotalProvider,
    UrlscanProvider,
    CensysProvider,
    FofaProvider,
]


def build_providers() -> dict[str, BaseProvider]:
    return {cls.name: cls() for cls in PROVIDER_CLASSES}
