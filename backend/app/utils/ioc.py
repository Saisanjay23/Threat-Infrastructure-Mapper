"""IOC detection, refanging and normalisation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import tldextract

from app.models.common import IOCType

# Offline extractor: uses the public-suffix snapshot bundled with tldextract (no network fetch).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{2,59})$"
)
_HASH_RE = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")


class InvalidIOCError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedIOC:
    raw: str
    type: IOCType
    value: str  # normalised canonical value
    host: str | None  # domain or IP the IOC resolves to (None for certificate hashes)
    url: str | None  # URL to fetch for web collection

    @property
    def is_ip_host(self) -> bool:
        return self.host is not None and is_ip(self.host)


def refang(value: str) -> str:
    v = value.strip().strip("\"'<>")
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = re.sub(r"^fxp", "ftp", v, flags=re.IGNORECASE)
    for pattern in (r"\[\.\]", r"\(\.\)", r"\{\.\}", r"\[dot\]", r"\(dot\)"):
        v = re.sub(pattern, ".", v, flags=re.IGNORECASE)
    v = v.replace("[:]", ":").replace("[://]", "://").replace("[/]", "/")
    return v


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    d = value.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidIOCError(f"Invalid internationalised domain: {value}") from exc
    if not _DOMAIN_RE.match(d):
        raise InvalidIOCError(f"Invalid domain: {value}")
    return d


def is_domain(value: str) -> bool:
    try:
        normalize_domain(value)
        return True
    except InvalidIOCError:
        return False


def registered_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1), e.g. login.example.co.uk -> example.co.uk."""
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host.lower()


def normalize_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise InvalidIOCError(f"Unsupported URL scheme: {parts.scheme or '(none)'}")
    if not parts.hostname:
        raise InvalidIOCError(f"URL has no host: {value}")
    host = parts.hostname
    host = host if is_ip(host) else normalize_domain(host)
    netloc = host if ":" not in host else f"[{host}]"
    if parts.port and not (
        (parts.scheme.lower() == "http" and parts.port == 80) or (parts.scheme.lower() == "https" and parts.port == 443)
    ):
        netloc = f"{netloc}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def parse_ioc(raw: str) -> ParsedIOC:
    value = refang(raw)
    if not value:
        raise InvalidIOCError("Empty IOC")

    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        url = normalize_url(value)
        host = urlsplit(url).hostname or ""
        return ParsedIOC(raw=raw, type=IOCType.URL, value=url, host=host, url=url)

    compact = lowered.replace(":", "")
    if _HASH_RE.match(compact):
        return ParsedIOC(raw=raw, type=IOCType.CERTIFICATE, value=compact, host=None, url=None)

    if is_ip(value):
        ip = str(ipaddress.ip_address(value.strip("[]")))
        host_part = f"[{ip}]" if ":" in ip else ip
        return ParsedIOC(raw=raw, type=IOCType.IP, value=ip, host=ip, url=f"http://{host_part}/")

    # bare host with a path, e.g. example.com/login
    if "/" in value:
        return parse_ioc(f"http://{value}")

    domain = normalize_domain(value)
    return ParsedIOC(raw=raw, type=IOCType.DOMAIN, value=domain, host=domain, url=f"https://{domain}/")


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global
