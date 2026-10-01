"""Collectors against a local aiohttp HTTP/TLS server; DNS/Cymru/WHOIS with patched resolvers."""

from __future__ import annotations

import datetime as dt
import ssl
from collections.abc import AsyncIterator

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.collectors import favicon as favicon_mod
from app.collectors import tls as tls_mod
from app.collectors import web as web_mod
from app.core.config import get_settings
from app.models.common import IOCType
from app.providers.base import ProviderContext
from app.providers.free import cymru as cymru_mod
from app.providers.free import dns_provider as dns_mod
from app.providers.free import whois as whois_mod
from app.utils.ioc import parse_ioc
from tests.helpers import PHISH_HTML, png_bytes

FAVICON = png_bytes((0, 120, 200))


async def _app() -> web.Application:
    async def index(_: web.Request) -> web.Response:
        return web.Response(
            status=302, headers={"Location": "/meta", "Set-Cookie": "sid=abc; Path=/; HttpOnly; Secure"}
        )

    async def meta(_: web.Request) -> web.Response:
        return web.Response(
            text='<html><head><meta http-equiv="refresh" content="0; url=/login"></head></html>',
            content_type="text/html",
        )

    async def login(_: web.Request) -> web.Response:
        return web.Response(
            text=PHISH_HTML.replace("/static/fav.png", "/fav.png"),
            content_type="text/html",
            headers={"Server": "test-nginx"},
        )

    async def fav(_: web.Request) -> web.Response:
        return web.Response(body=FAVICON, content_type="image/png")

    async def loop(_: web.Request) -> web.Response:
        return web.Response(status=301, headers={"Location": "/loop"})

    async def notfound_ico(_: web.Request) -> web.Response:
        return web.Response(text="<html>not an icon</html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/meta", meta)
    app.router.add_get("/login", login)
    app.router.add_get("/fav.png", fav)
    app.router.add_get("/loop", loop)
    app.router.add_get("/favicon.ico", notfound_ico)
    return app


def _self_signed(tmp_path) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("alt.localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(cert_path), str(key_path)


@pytest.fixture
async def server(tmp_path) -> AsyncIterator[dict[str, int]]:
    runner = web.AppRunner(await _app())
    await runner.setup()
    http = web.TCPSite(runner, "127.0.0.1", 0)
    await http.start()
    cert, key = _self_signed(tmp_path)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    tls = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ctx)
    await tls.start()
    ports = {"http": http._server.sockets[0].getsockname()[1], "https": tls._server.sockets[0].getsockname()[1]}  # type: ignore[union-attr]
    yield ports
    await runner.cleanup()


@pytest.fixture
def allow_private(monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_private_targets", True)


async def test_fetch_page_follows_redirects_meta_refresh_and_cookies(server, allow_private):
    base = f"http://127.0.0.1:{server['http']}"
    page = await web_mod.fetch_page(base + "/")
    assert page.ok and page.status_code == 200
    assert page.final_url == base + "/login"
    assert [h.kind for h in page.redirect_chain] == ["http", "meta-refresh", "http"]
    assert page.redirect_chain[0].status == 302
    assert page.cookies[0]["name"] == "sid" and page.cookies[0]["httponly"] is True
    assert "Contoso Bank" in page.html and page.headers["server"] == "test-nginx"
    assert page.to_dict()["body_size"] == len(page.body) and "html" not in page.to_dict()


async def test_fetch_page_detects_redirect_loop(server, allow_private):
    page = await web_mod.fetch_page(f"http://127.0.0.1:{server['http']}/loop")
    assert page.error == "redirect loop detected"


async def test_ssrf_guard_blocks_private_targets(server):
    assert get_settings().allow_private_targets is False
    page = await web_mod.fetch_page(f"http://127.0.0.1:{server['http']}/")
    assert page.error and page.error.startswith("blocked:")
    assert await web_mod.fetch_binary(f"http://127.0.0.1:{server['http']}/fav.png") is None
    with pytest.raises(web_mod.BlockedTargetError):
        await web_mod.assert_public_target("http://localhost/")


async def test_favicon_discovery_and_download(server, allow_private):
    base = f"http://127.0.0.1:{server['http']}"
    html = '<link rel="shortcut icon" href="/fav.png"><link rel="icon" href="data:image/png;base64,AAAA">'
    assert favicon_mod.discover_favicon_urls(html, base + "/x") == [base + "/fav.png", base + "/favicon.ico"]
    icon = await favicon_mod.fetch_favicon(html, base + "/")
    assert icon is not None and icon.content == FAVICON and icon.format == "PNG" and icon.width == 32
    # /favicon.ico serves HTML: rejected as not an image.
    assert await favicon_mod.fetch_favicon("", base + "/") is None


async def test_tls_collection_and_parsing(server):
    result = await tls_mod.collect_tls("127.0.0.1", server["https"], timeout=5)
    cert = result["certificate"]
    assert cert["subject_cn"] == "localhost" and cert["self_signed"] is True
    assert cert["san"] == ["alt.localhost", "localhost"] and cert["key_type"] == "RSA" and cert["key_size"] == 2048
    assert len(cert["sha256"]) == 64 and result["trusted"] is False and result["validation_error"]
    assert result["protocol"].startswith("TLS")
    failed = await tls_mod.collect_tls("127.0.0.1", server["http"], timeout=5)
    assert "error" in failed


def test_cookie_and_charset_helpers():
    cookies = web_mod.parse_set_cookie(["a=1; Domain=x.test; SameSite=Lax", "bad cookie;;=="])
    assert cookies[0]["domain"] == "x.test" and cookies[0]["samesite"] == "Lax"
    assert web_mod.decode_body("caf\xe9".encode("latin-1"), "text/html; charset=latin-1") == "café"
    assert web_mod.decode_body(b'<meta charset="utf-8">\xc3\xa9', None).endswith("é")


async def test_dns_provider_records(monkeypatch):
    answers = {
        ("example.test", "A"): ["192.0.2.10"],
        ("example.test", "AAAA"): ["2001:db8::10"],
        ("example.test", "MX"): ["10 mail.example.test."],
        ("example.test", "NS"): ["ns1.example.test."],
        ("example.test", "TXT"): ['"v=spf1 -all"'],
        ("example.test", "CNAME"): ["edge.cdn.test."],
        ("10.2.0.192.in-addr.arpa.", "PTR"): ["host.example.test."],
    }

    async def fake_resolve(_resolver, name, rtype):
        return answers.get((name, rtype), [])

    monkeypatch.setattr(dns_mod, "resolve", fake_resolve)
    p = dns_mod.DNSProvider()
    c = ProviderContext(session=None, timeout=5)  # type: ignore[arg-type]
    r = await p.query(parse_ioc("example.test"), c)
    assert r.summary["a"] == ["192.0.2.10"] and r.summary["spf"] == "v=spf1 -all" and r.summary["resolves"]
    rels = {(e.type, e.value, e.relation.value) for e in r.related}
    assert ("ip", "2001:db8::10", "RESOLVES_TO") in rels and ("domain", "mail.example.test", "USES_MX") in rels
    assert ("nameserver", "ns1.example.test", "USES_NAMESERVER") in rels and (
        "domain",
        "edge.cdn.test",
        "CNAME_TO",
    ) in rels
    ptr = await p.query(parse_ioc("192.0.2.10"), c)
    assert ptr.summary["ptr"] == ["host.example.test"] and ptr.related[0].reverse
    assert p.supports(IOCType.URL)


async def test_cymru_provider(monkeypatch):
    async def fake_resolve(_resolver, name, rtype):
        if name.endswith("origin.asn.cymru.com"):
            return ['"64500 | 192.0.2.0/24 | ZZ | test | 2020-01-01"']
        if name == "AS64500.asn.cymru.com":
            return ['"64500 | ZZ | test | 2020-01-01 | EXAMPLE-AS - Example Hosting Ltd, ZZ"']
        return []

    monkeypatch.setattr(cymru_mod, "resolve", fake_resolve)
    r = await cymru_mod.TeamCymruProvider().query(parse_ioc("192.0.2.1"), ProviderContext(session=None))  # type: ignore[arg-type]
    assert r.summary["asn"] == "AS64500" and r.summary["hosting_provider"] == "Example Hosting Ltd"
    assert {e.type for e in r.related} == {"asn", "hosting"}

    async def empty(*_a):
        return []

    monkeypatch.setattr(cymru_mod, "resolve", empty)
    assert (
        await cymru_mod.TeamCymruProvider().query(parse_ioc("192.0.2.1"), ProviderContext(session=None))
    ).summary == {"found": False}  # type: ignore[arg-type]


async def test_whois_referral_chain(monkeypatch):
    replies = {
        "whois.iana.org": "refer: whois.registry.test\n",
        "whois.registry.test": "Registrar WHOIS Server: whois.registrar.test\nwhois: whois.registrar.test\n",
        "whois.registrar.test": "Registrar: Demo Registrar\nCreation Date: 2024-01-01\nName Server: NS1.DEMO.TEST\n",
    }
    seen: list[str] = []

    async def fake_query(server, query, timeout=10.0):
        seen.append(server)
        return replies[server]

    monkeypatch.setattr(whois_mod, "whois_query", fake_query)
    r = await whois_mod.WhoisProvider().query(parse_ioc("sub.example.test"), ProviderContext(session=None))  # type: ignore[arg-type]
    assert seen == ["whois.iana.org", "whois.registry.test", "whois.registrar.test"]
    assert r.summary["registrar"] == "Demo Registrar" and r.related[0].value == "ns1.demo.test"


async def test_whois_socket_errors():
    with pytest.raises(whois_mod.ProviderError):
        await whois_mod.whois_query("127.0.0.1", "example.test", timeout=1)  # nothing listens on port 43


def test_dns_resolver_fallback(monkeypatch):
    import dns.resolver

    def broken(*_a, **_k):
        raise dns.resolver.NoResolverConfiguration

    real = dns_mod.dns.asyncresolver.Resolver
    monkeypatch.setattr(
        dns_mod.dns.asyncresolver, "Resolver", lambda configure=True: broken() if configure else real(configure=False)
    )
    resolver = dns_mod.make_resolver(4)
    assert resolver.nameservers == dns_mod.FALLBACK_NAMESERVERS and resolver.lifetime == 4
