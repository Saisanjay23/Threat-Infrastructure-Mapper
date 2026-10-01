"""HTTP collection with browser TLS impersonation (curl_cffi), manual redirect tracking and SSRF guard."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import asdict, dataclass, field
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlsplit

from curl_cffi import requests as creq
from curl_cffi.requests.exceptions import RequestException

from app.core.config import get_settings

_META_REFRESH_RE = re.compile(
    r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?\s*\d+\s*;\s*url=([^\"'>\s]+)", re.IGNORECASE
)
_META_CHARSET_RE = re.compile(rb"<meta[^>]+charset=[\"']?([A-Za-z0-9_\-]+)", re.IGNORECASE)
_JS_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']|location\.replace\([\"']([^\"']+)[\"']\)",
    re.IGNORECASE,
)


class BlockedTargetError(Exception):
    """Raised when a URL resolves to a non-public address and private targets are not allowed."""


@dataclass
class RedirectHop:
    url: str
    status: int
    location: str | None = None
    kind: str = "http"  # http | meta-refresh
    ip: str | None = None
    server: str | None = None


@dataclass
class PageFetch:
    requested_url: str
    final_url: str | None = None
    status_code: int | None = None
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    content_type: str | None = None
    body: bytes = b""
    html: str = ""
    truncated: bool = False
    ip: str | None = None
    elapsed_ms: float = 0.0
    http_version: str | None = None
    js_redirect_hints: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("body", None)
        data.pop("html", None)
        data["body_size"] = len(self.body)
        return data


def _is_public(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


async def assert_public_target(url: str) -> None:
    if get_settings().allow_private_targets:
        return
    host = urlsplit(url).hostname
    if not host:
        raise BlockedTargetError(f"URL has no host: {url}")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise BlockedTargetError(f"DNS resolution failed for {host}: {exc}") from exc
        addrs = sorted({str(i[4][0]) for i in infos})
    blocked = [a for a in addrs if not _is_public(a)]
    if blocked:
        raise BlockedTargetError(f"{host} resolves to non-public address(es) {', '.join(blocked)}")


def parse_set_cookie(header_values: list[str]) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for raw in header_values:
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            name = raw.split("=", 1)[0].strip()
            cookies.append({"name": name, "raw": raw[:500]})
            continue
        for name, morsel in jar.items():
            cookies.append(
                {
                    "name": name,
                    "value_preview": morsel.value[:64],
                    "domain": morsel["domain"] or None,
                    "path": morsel["path"] or None,
                    "expires": morsel["expires"] or None,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                }
            )
    return cookies


def decode_body(body: bytes, content_type: str | None) -> str:
    charset = None
    if content_type and "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=")[-1].split(";")[0].strip().strip("\"'")
    if not charset:
        m = _META_CHARSET_RE.search(body[:4096])
        if m:
            charset = m.group(1).decode("ascii", "ignore")
    for enc in (charset, "utf-8", "latin-1"):
        if not enc:
            continue
        try:
            return body.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def _fetch_sync(url: str, timeout: float, max_bytes: int, user_agent: str) -> tuple[creq.Response, bytes, bool]:
    with creq.Session(impersonate="chrome") as session:
        resp = session.get(
            url,
            allow_redirects=False,
            timeout=timeout,
            verify=False,
            stream=True,
            headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        chunks: list[bytes] = []
        size = 0
        truncated = False
        try:
            for chunk in resp.iter_content():
                chunks.append(chunk)
                size += len(chunk)
                if size >= max_bytes:
                    truncated = True
                    break
        finally:
            resp.close()
        return resp, b"".join(chunks)[:max_bytes], truncated


async def fetch_page(url: str, *, follow_meta_refresh: bool = True) -> PageFetch:
    settings = get_settings()
    result = PageFetch(requested_url=url)
    current = url
    start = time.perf_counter()
    seen: set[str] = set()
    try:
        for _ in range(settings.max_redirects + 1):
            await assert_public_target(current)
            seen.add(current)
            resp, body, truncated = await asyncio.to_thread(
                _fetch_sync, current, settings.http_timeout_seconds, settings.max_html_bytes, settings.user_agent
            )
            headers = {k.lower(): v or "" for k, v in resp.headers.items()}
            # Cookies are collected on every hop: kits commonly tag visitors on the first redirect.
            result.cookies.extend(
                {**c, "set_by": current}
                for c in parse_set_cookie([v for v in resp.headers.get_list("set-cookie") if v])
            )
            hop = RedirectHop(
                url=current,
                status=resp.status_code,
                ip=getattr(resp, "primary_ip", None) or None,
                server=headers.get("server"),
            )
            location = headers.get("location")
            if 300 <= resp.status_code < 400 and location:
                hop.location = urljoin(current, location)
                result.redirect_chain.append(hop)
                current = hop.location
                if current in seen:
                    result.error = "redirect loop detected"
                    break
                continue

            content_type = headers.get("content-type")
            html = decode_body(body, content_type) if body else ""
            if follow_meta_refresh and html:
                m = _META_REFRESH_RE.search(html[:20000])
                if m:
                    target = urljoin(current, m.group(1).strip())
                    if target not in seen and target.startswith(("http://", "https://")):
                        hop.location = target
                        hop.kind = "meta-refresh"
                        result.redirect_chain.append(hop)
                        current = target
                        continue

            result.redirect_chain.append(hop)
            result.final_url = current
            result.status_code = resp.status_code
            result.headers = headers
            result.content_type = content_type
            result.body = body
            result.html = html
            result.truncated = truncated
            result.ip = hop.ip
            result.http_version = str(getattr(resp, "http_version", "") or "") or None
            result.js_redirect_hints = sorted(
                {g for m in _JS_REDIRECT_RE.finditer(html[:200000]) for g in m.groups() if g}
            )[:20]
            break
        else:
            result.error = f"too many redirects (>{settings.max_redirects})"
    except BlockedTargetError as exc:
        result.error = f"blocked: {exc}"
    except RequestException as exc:
        result.error = f"request failed: {exc}"
    except (OSError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    result.elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    if result.final_url is None and result.redirect_chain:
        result.final_url = result.redirect_chain[-1].location or result.redirect_chain[-1].url
    return result


async def fetch_binary(url: str, max_bytes: int = 2 * 1024 * 1024) -> tuple[int, bytes, str | None] | None:
    """Fetch a small binary resource (favicon/logo). Follows redirects. Returns (status, body, content_type)."""
    settings = get_settings()
    current = url
    try:
        for _ in range(6):
            await assert_public_target(current)  # re-checked on every hop
            resp, body, _ = await asyncio.to_thread(
                _fetch_sync, current, settings.http_timeout_seconds, max_bytes, settings.user_agent
            )
            location = resp.headers.get("location")
            if 300 <= resp.status_code < 400 and location:
                current = urljoin(current, location)
                continue
            return resp.status_code, body, resp.headers.get("content-type")
    except (BlockedTargetError, RequestException, OSError, ValueError):
        return None
    return None
