"""Provider HTTP behaviour with a scripted fake aiohttp session (no network)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.models.graph import RelationType
from app.providers.base import ProviderContext, ProviderError, ProviderNotConfiguredError, ProviderRateLimitedError
from app.providers.credit.censys import CensysProvider
from app.providers.credit.fofa import FofaProvider
from app.providers.credit.urlscan import UrlscanProvider
from app.providers.credit.virustotal import VirusTotalProvider
from app.providers.free.abuseipdb import AbuseIPDBProvider
from app.providers.free.crtsh import CrtShProvider
from app.providers.free.greynoise import GreyNoiseProvider
from app.providers.free.rdap import RDAPProvider
from app.providers.free.wayback import WaybackProvider
from app.utils.ioc import parse_ioc


class FakeResponse:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self._body = body

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def json(self, content_type: str | None = None) -> Any:
        if isinstance(self._body, str):
            return json.loads(self._body)
        return self._body

    async def text(self) -> str:
        return self._body if isinstance(self._body, str) else json.dumps(self._body)


class FakeSession:
    """Routes GET requests by URL substring to queued (status, body) responses."""

    def __init__(self, routes: dict[str, list[tuple[int, Any]] | tuple[int, Any]]) -> None:
        self.routes = {k: (v if isinstance(v, list) else [v]) for k, v in routes.items()}
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        for key, queue in self.routes.items():
            if key in url:
                status, body = queue.pop(0) if len(queue) > 1 else queue[0]
                return FakeResponse(status, body)
        return FakeResponse(404, {"error": "no route"})


def ctx(routes: dict, key: str | None = None, secret: str | None = None) -> tuple[ProviderContext, FakeSession]:
    session = FakeSession(routes)
    return ProviderContext(session=session, api_key=key, api_secret=secret, timeout=5), session  # type: ignore[arg-type]


async def test_base_get_json_errors_and_retry(monkeypatch):
    monkeypatch.setattr("app.providers.base.asyncio.sleep", _no_sleep)
    p = RDAPProvider()
    c, s = ctx({"/retry": [(503, "busy"), (200, {"ok": True})]})
    assert await p.get_json(c, "https://x/retry") == {"ok": True}
    assert len(s.calls) == 2
    with pytest.raises(ProviderNotConfiguredError):
        await p.get_json(ctx({"/a": (401, "no")})[0], "https://x/a")
    with pytest.raises(ProviderRateLimitedError):
        await p.get_json(ctx({"/a": (429, "slow")})[0], "https://x/a")
    with pytest.raises(ProviderError, match="HTTP 500"):
        await p.get_json(ctx({"/a": (500, "boom")})[0], "https://x/a")
    with pytest.raises(ProviderError, match="not JSON"):
        await p.get_json(ctx({"/a": (200, "<html>")})[0], "https://x/a")
    assert await p.get_json(ctx({"/a": (404, "")})[0], "https://x/a", allow_404=True) is None
    with pytest.raises(ProviderError, match="HTTP 502"):
        await p.get_json(ctx({"/a": (502, "x")})[0], "https://x/a", retries=0)
    assert await p.get_text(ctx({"/t": (200, "hello")})[0], "https://x/t") == "hello"
    with pytest.raises(ProviderError):
        await p.get_text(ctx({"/t": (500, "x")})[0], "https://x/t")


async def _no_sleep(_s: float) -> None:
    return None


async def test_rdap_domain_and_ip():
    domain_doc = {
        "handle": "D1",
        "status": ["active"],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01"},
            {"eventAction": "expiration", "eventDate": "2030-01-01"},
        ],
        "secureDNS": {"delegationSigned": False},
        "notices": ["drop me"],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]]}],
    }
    c, _ = ctx({"/domain/": (200, domain_doc)})
    r = await RDAPProvider().query(parse_ioc("login.example.test"), c)
    assert r.summary["registrar"] == "Reg Inc" and r.summary["created"] == "2020-01-01"
    assert r.related[0].value == "ns1.example.test" and "notices" not in r.raw
    ip_doc = {
        "name": "NET-1",
        "handle": "N1",
        "startAddress": "192.0.2.0",
        "endAddress": "192.0.2.255",
        "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
        "country": "ZZ",
        "type": "ALLOCATED",
    }
    r = await RDAPProvider().query(parse_ioc("192.0.2.5"), ctx({"/ip/": (200, ip_doc)})[0])
    assert r.summary["cidr"] == ["192.0.2.0/24"] and r.summary["network_name"] == "NET-1"
    assert (await RDAPProvider().query(parse_ioc("192.0.2.5"), ctx({})[0])).summary == {"found": False}
    assert (await RDAPProvider().query(parse_ioc("x.test"), ctx({})[0])).summary["found"] is False


async def test_crtsh_domain_and_certificate_page():
    entries = [
        {
            "id": 9,
            "issuer_name": "O=CA",
            "common_name": "a.example.test",
            "name_value": "a.example.test\nother.test",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
            "serial_number": "1",
        }
    ]
    r = await CrtShProvider().query(parse_ioc("example.test"), ctx({"crt.sh": (200, entries)})[0])
    assert r.summary["certificate_count"] == 1
    page = "<a href='?id=123'>x</a> DNS:alpha.example.test<BR>DNS:*.beta.example.test"
    r = await CrtShProvider().pivot_search("cert_sha256", "a" * 64, ctx({"crt.sh": (200, page)})[0])
    assert r.summary["crtsh_id"] == "123"
    assert {e.value for e in r.related} == {"alpha.example.test", "beta.example.test"}
    assert all(e.relation == RelationType.USES_CERTIFICATE and e.reverse for e in r.related)
    r = await CrtShProvider().query(parse_ioc("b" * 40), ctx({"crt.sh": (200, page)})[0])
    assert r.summary["found"] is True


async def test_wayback_cdx_and_fallback():
    rows = [
        ["timestamp", "original", "statuscode", "mimetype", "digest"],
        ["20200101000000", "http://a.test/", "200", "text/html", "D1"],
        ["20240101000000", "http://a.test/", "200", "text/html", "D2"],
    ]
    r = await WaybackProvider().query(parse_ioc("a.test"), ctx({"/cdx/": (200, rows)})[0])
    assert r.summary["snapshot_count"] == 2 and r.summary["distinct_content_versions"] == 2
    assert r.summary["first_seen"].startswith("2020-01-01")
    avail = {
        "archived_snapshots": {
            "closest": {"timestamp": "20250101000000", "url": "http://web.archive.org/x", "status": "200"}
        }
    }
    r = await WaybackProvider().query(
        parse_ioc("a.test"), ctx({"/cdx/": (500, "down"), "wayback/available": (200, avail)})[0]
    )
    assert r.summary["partial"] is True and r.summary["snapshot_count"] == 1


async def test_abuseipdb_and_greynoise():
    with pytest.raises(ProviderNotConfiguredError):
        await AbuseIPDBProvider().query(parse_ioc("192.0.2.1"), ctx({})[0])
    data = {
        "data": {
            "abuseConfidenceScore": 87,
            "totalReports": 12,
            "hostnames": ["bad.example.test"],
            "countryCode": "ZZ",
            "isTor": False,
        }
    }
    c, s = ctx({"abuseipdb": (200, data)}, key="k")
    r = await AbuseIPDBProvider().query(parse_ioc("192.0.2.1"), c)
    assert r.summary["abuse_confidence_score"] == 87 and r.related[0].value == "bad.example.test"
    assert s.calls[0]["headers"]["Key"] == "k"

    gn = {"noise": True, "riot": False, "classification": "malicious", "name": "scanner"}
    r = await GreyNoiseProvider().query(parse_ioc("192.0.2.1"), ctx({"greynoise": (200, gn)}, key="g")[0])
    assert r.summary["seen"] is True and r.summary["classification"] == "malicious"
    assert (await GreyNoiseProvider().query(parse_ioc("192.0.2.1"), ctx({})[0])).summary["seen"] is False
    assert "IPv4" in (await GreyNoiseProvider().query(parse_ioc("2001:db8::1"), ctx({})[0])).summary["note"]


async def test_virustotal_domain_url_ip_and_cert():
    attrs = {
        "last_analysis_stats": {"malicious": 4, "harmless": 50},
        "reputation": -10,
        "registrar": "Reg",
        "last_https_certificate": {"thumbprint_sha256": "AB" * 32, "issuer": {"O": "CA"}},
        "last_dns_records": [{"type": "A", "value": "192.0.2.9"}, {"type": "NS", "value": "ns.example.test."}],
        "last_analysis_results": {"drop": 1},
    }
    c, s = ctx({"/domains/": (200, {"data": {"attributes": attrs}})}, key="vt")
    r = await VirusTotalProvider().query(parse_ioc("a.test"), c)
    assert r.summary["malicious"] == 4 and r.credits_used == 1
    assert {(e.type, e.value) for e in r.related} >= {
        ("ip", "192.0.2.9"),
        ("nameserver", "ns.example.test"),
        ("certificate", "ab" * 32),
    }
    assert "last_analysis_results" not in r.raw["attributes"] and s.calls[0]["headers"]["x-apikey"] == "vt"
    url_ctx, url_s = ctx({"/urls/": (404, "")}, key="vt")
    assert (await VirusTotalProvider().query(parse_ioc("https://a.test/x"), url_ctx)).summary == {"found": False}
    assert "/urls/" in url_s.calls[0]["url"]
    assert (
        await VirusTotalProvider().query(
            parse_ioc("192.0.2.1"), ctx({"/ip_addresses/": (200, {"data": {"attributes": {}}})}, key="vt")[0]
        )
    ).summary["found"]
    search = {"data": [{"id": "x.example.test"}, {"id": "not a domain"}]}
    r = await VirusTotalProvider().query(parse_ioc("c" * 64), ctx({"intelligence/search": (200, search)}, key="vt")[0])
    assert [e.value for e in r.related] == ["x.example.test"]


async def test_urlscan_query_and_pivots():
    results = {
        "total": 1,
        "results": [
            {
                "_id": "u1",
                "task": {"time": "2026-01-01"},
                "page": {"domain": "kit.example.test", "ip": "192.0.2.3", "title": "Login"},
                "screenshot": "https://urlscan.io/screenshots/u1.png",
            }
        ],
    }
    c, s = ctx({"urlscan.io": (200, results)}, key="us")
    r = await UrlscanProvider().query(parse_ioc("a.test"), c)
    assert r.summary["total"] == 1 and s.calls[0]["params"]["q"] == 'domain:"a.test"'
    assert s.calls[0]["headers"]["API-Key"] == "us"
    await UrlscanProvider().query(parse_ioc("192.0.2.1"), c)
    assert s.calls[-1]["params"]["q"] == 'ip:"192.0.2.1"'
    r = await UrlscanProvider().pivot_search("title", 'Secure "Login"', c)
    assert s.calls[-1]["params"]["q"] == 'page.title:"Secure \\"Login\\""'
    assert r.related[0].relation == RelationType.SIMILAR_TITLE
    with pytest.raises(ProviderError):
        await UrlscanProvider().pivot_search("cert_sha1", "x", c)


async def test_fofa_queries_and_errors():
    payload = {
        "error": False,
        "size": 2,
        "results": [
            [
                "https://kit.example.test:443",
                "192.0.2.4",
                "443",
                "kit.example.test",
                "Login",
                "nginx",
                "ZZ",
                "64500",
                "AS",
            ]
        ],
    }
    c, s = ctx({"fofa.info": (200, payload)}, key="f", secret="me@example.test")
    r = await FofaProvider().pivot_search("favicon_mmh3", "-123", c)
    import base64

    assert base64.b64decode(s.calls[0]["params"]["qbase64"]).decode() == 'icon_hash="-123"'
    assert s.calls[0]["params"]["email"] == "me@example.test"
    assert {(e.type, e.value) for e in r.related} == {("domain", "kit.example.test"), ("ip", "192.0.2.4")}
    await FofaProvider().pivot_search("tracking_id", "UA-1-1", c)
    assert base64.b64decode(s.calls[-1]["params"]["qbase64"]).decode() == 'body="UA-1-1"'
    for ioc in ("192.0.2.1", "a.test", "d" * 64):
        await FofaProvider().query(parse_ioc(ioc), c)
    err, _ = ctx({"fofa.info": (200, {"error": True, "errmsg": "bad key"})}, key="f")
    with pytest.raises(ProviderError, match="bad key"):
        await FofaProvider().query(parse_ioc("a.test"), err)
    with pytest.raises(ProviderError):
        await FofaProvider().pivot_search("asn", "x", c)


async def test_censys_platform_and_legacy():
    host = {
        "result": {
            "resource": {
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTP",
                        "transport_protocol": "TCP",
                        "software": [{"product": "nginx"}],
                        "tls": {"certificates": {"leaf_fp_sha_256": "EE" * 32}},
                    }
                ],
                "autonomous_system": {"asn": 64500, "name": "EX"},
                "location": {"country": "ZZ"},
                "dns": {"names": ["a.example.test", "bad name"]},
            }
        }
    }
    c, s = ctx({"/host/": (200, host)}, key="pat")
    r = await CensysProvider().query(parse_ioc("192.0.2.1"), c)
    assert r.summary["asn"] == "AS64500" and r.summary["services"][0]["cert_sha256"] == "EE" * 32
    assert s.calls[0]["headers"]["Authorization"] == "Bearer pat"
    assert {e.type for e in r.related} == {"domain", "certificate"}
    legacy, ls = ctx(
        {"/hosts/": (200, {"result": {"services": [{"port": 22, "cert": {"fingerprint_sha256": "aa"}}]}})},
        key="id",
        secret="sec",
    )
    r = await CensysProvider().query(parse_ioc("192.0.2.1"), legacy)
    import base64

    assert ls.calls[0]["headers"]["Authorization"] == "Basic " + base64.b64encode(b"id:sec").decode()
    assert r.summary["services"][0]["cert_sha256"] == "aa"
    cert = {"result": {"names": ["*.kit.example.test"], "parsed": {"issuer_dn": "CA", "subject_dn": "S"}}}
    r = await CensysProvider().query(parse_ioc("f" * 64), ctx({"/certificate/": (200, cert)}, key="pat")[0])
    assert r.related[0].value == "kit.example.test"
    assert (await CensysProvider().query(parse_ioc("192.0.2.1"), ctx({}, key="pat")[0])).summary == {"found": False}
    assert (await CensysProvider().query(parse_ioc("f" * 64), ctx({}, key="pat")[0])).summary == {"found": False}


async def test_fofa_steps_down_fields_on_permission_error(monkeypatch):
    monkeypatch.setattr(FofaProvider, "_tier", 0)
    denied = {"error": True, "errmsg": "[820001] 没有权限搜索as_number字段"}
    ok = {"error": False, "size": 1, "results": [["kit.example.test", "192.0.2.8", "443", "kit.example.test", "Login",
                                                  "nginx", "ZZ"]]}
    c, s = ctx({"fofa.info": [(200, denied), (200, ok)]}, key="f")
    r = await FofaProvider().query(parse_ioc("kit.example.test"), c)
    assert "as_number" in s.calls[0]["params"]["fields"] and "as_number" not in s.calls[1]["params"]["fields"]
    assert r.summary["fields"][-1] == "country" and FofaProvider._tier == 1
    c2, s2 = ctx({"fofa.info": (200, ok)}, key="f")
    await FofaProvider().query(parse_ioc("kit.example.test"), c2)
    assert len(s2.calls) == 1 and "as_number" not in s2.calls[0]["params"]["fields"]  # remembered tier
    bad, _ = ctx({"fofa.info": (200, {"error": True, "errmsg": "[-700] Account Invalid"})}, key="f")
    with pytest.raises(ProviderError, match="invalid FOFA API key"):
        await FofaProvider().query(parse_ioc("a.test"), bad)
