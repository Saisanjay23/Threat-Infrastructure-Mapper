"""End-to-end pipeline test with all network collectors replaced by offline fakes."""

from __future__ import annotations

import asyncio

import pytest

from app.collectors.favicon import Favicon
from app.collectors.tls import parse_certificate
from app.collectors.web import PageFetch, RedirectHop
from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.models.investigation import InvestigationOptions
from app.pipeline.runner import PipelineRunner
from app.pipeline.stages.collection import CollectionStage
from app.pipeline.stages.enrichment import EnrichmentStage
from app.providers.base import BaseProvider, ProviderContext, ProviderResult
from app.providers.manager import ProviderManager
from app.services.progress import ProgressHub
from app.utils.ioc import ParsedIOC
from tests.helpers import PHISH_HTML, png_bytes, self_signed_der

CERT_DER = self_signed_der()


class FakeDNS(BaseProvider):
    name = "dns"
    display_name = "dns"
    description = "fake"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.IP})
    default_priority = 1

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        if ioc.type == IOCType.IP:
            return ProviderResult(summary={"ptr": ["host.example-cloud.test"]})
        return ProviderResult(
            summary={"a": ["93.184.215.14"], "aaaa": [], "ns": ["ns1.bulletproof.test"], "mx": []},
            related=[
                RelatedEntity(type="ip", value="93.184.215.14", relation=RelationType.RESOLVES_TO),
                RelatedEntity(type="nameserver", value="ns1.bulletproof.test", relation=RelationType.USES_NAMESERVER),
            ],
        )


class FakeCymru(BaseProvider):
    name = "cymru"
    display_name = "cymru"
    description = "fake"
    supported_types = frozenset({IOCType.IP})
    default_priority = 4

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        return ProviderResult(
            summary={
                "asn": "AS64500",
                "as_name": "EXAMPLE-AS - Example Hosting, US",
                "hosting_provider": "Example Hosting",
                "country": "US",
                "prefix": "203.0.113.0/24",
            },
            related=[
                RelatedEntity(type="asn", value="AS64500", relation=RelationType.BELONGS_TO_ASN),
                RelatedEntity(type="hosting", value="Example Hosting", relation=RelationType.HOSTED_ON),
            ],
        )


class FakeCT(BaseProvider):
    name = "crtsh"
    display_name = "crtsh"
    description = "fake"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.URL})
    default_priority = 10

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        return ProviderResult(
            summary={"certificate_count": 1},
            related=[
                RelatedEntity(type="domain", value="contoso-verify.test", relation=RelationType.SHARES_CERTIFICATE)
            ],
        )


@pytest.fixture
def offline_collectors(monkeypatch):
    async def fake_fetch(url: str, **_: object) -> PageFetch:
        hops = [
            RedirectHop(url="https://phish.test/", status=302, location="https://login.phish.test/verify"),
            RedirectHop(url="https://login.phish.test/verify", status=200, ip="93.184.215.14", server="nginx"),
        ]
        return PageFetch(
            requested_url=url,
            final_url="https://login.phish.test/verify",
            status_code=200,
            redirect_chain=hops,
            headers={"server": "nginx", "content-type": "text/html"},
            cookies=[{"name": "sid"}],
            content_type="text/html",
            body=PHISH_HTML.encode(),
            html=PHISH_HTML,
            ip="93.184.215.14",
        )

    async def fake_tls(host: str, port: int = 443, timeout: float = 10.0) -> dict:
        return {
            "host": host,
            "port": port,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "certificate": parse_certificate(CERT_DER),
            "trusted": False,
            "validation_error": "self-signed",
        }

    async def fake_favicon(html: str, page_url: str, limit: int = 4) -> Favicon:
        return Favicon(
            url="https://login.phish.test/static/fav.png",
            content=png_bytes(),
            content_type="image/png",
            width=32,
            height=32,
            format="PNG",
        )

    monkeypatch.setattr("app.collectors.web.fetch_page", fake_fetch)
    monkeypatch.setattr("app.collectors.tls.collect_tls", fake_tls)
    monkeypatch.setattr("app.collectors.favicon.fetch_favicon", fake_favicon)


@pytest.fixture
async def runner(db):
    providers = {p.name: p for p in (FakeDNS(), FakeCymru(), FakeCT())}
    pm = ProviderManager(db, providers=providers)
    await pm.startup()
    hub = ProgressHub()
    r = PipelineRunner(db, pm, hub, stages=[CollectionStage(), EnrichmentStage()])
    yield r, hub
    await r.shutdown()
    await pm.shutdown()


async def test_full_collection_and_enrichment(db, runner, offline_collectors):
    r, hub = runner
    doc = r.new_document(
        "phish.test",
        InvestigationOptions(screenshots=False, credit_policy="never", brand="Contoso", brand_domains=["contoso.com"]),
        created_by="tester",
        tags=["unit"],
    )
    queue = hub.subscribe(doc["_id"])
    await r.submit(doc)
    await r.wait(doc["_id"], timeout=30)

    inv = await db["investigations"].find_one({"_id": doc["_id"]})
    assert inv["status"] == "completed", inv.get("error")
    assert inv["stages"]["collection"]["status"] == "completed"
    assert inv["stages"]["enrichment"]["status"] == "completed"
    assert inv["stages"]["pivot"]["status"] == "skipped"

    assets = await db["assets"].find({"investigation_ids": doc["_id"]}).to_list(length=None)
    by_type: dict[str, set[str]] = {}
    for a in assets:
        by_type.setdefault(a["type"], set()).add(a["value"])
    assert {"phish.test", "login.phish.test", "contoso-verify.test"} <= by_type["domain"]
    assert by_type["ip"] == {"93.184.215.14"}
    assert by_type["asn"] == {"AS64500"}
    assert by_type["hosting"] == {"Example Hosting"}
    assert by_type["nameserver"] == {"ns1.bulletproof.test"}
    assert len(by_type["certificate"]) == 1 and len(by_type["favicon"]) == 1
    assert "https://login.phish.test/verify" in by_type["url"]

    root = await db["assets"].find_one({"_id": inv["root_asset_id"]})
    assert root["type"] == "domain" and root["value"] == "phish.test"
    assert inv["summary"]["site_status"] == "ACTIVE"
    assert root["attributes"]["infrastructure"]["asns"] == ["AS64500"]
    assert root["fingerprints"]["nameservers"] == ["ns1.bulletproof.test"]
    final_host = next(a for a in assets if a["value"] == "login.phish.test")
    assert final_host["attributes"]["web"]["title"] == "Contoso Bank - Secure Login"
    assert final_host["fingerprints"]["favicon_mmh3"]
    assert final_host["fingerprints"]["cert_sha256"] == parse_certificate(CERT_DER)["sha256"]

    # Phase 2: fingerprints, trackers, content validation, brand impersonation
    assert by_type["analytics"] == {"G-ABC123XYZ9", "UA-1234567-1"}
    assert by_type["pixel"] == {"123456789012345"}
    assert final_host["status"] == "ACTIVE"
    assert final_host["fingerprints"]["analytics_ids"] == ["G-ABC123XYZ9", "UA-1234567-1"]
    assert final_host["fingerprints"]["pixel_ids"] == ["123456789012345"]
    assert final_host["fingerprints"]["title_hash"] and final_host["fingerprints"]["html_simhash"]
    assert final_host["attributes"]["website"]["has_login_form"] is True
    assert final_host["attributes"]["brand"]["signals"]["login_form"] is True
    assert final_host["impersonation_score"] >= 50
    assert root["status"] == "ACTIVE" and root["impersonation_score"] == final_host["impersonation_score"]

    rel_types = {e["type"] for e in await db["relationships"].find({"investigation_ids": doc["_id"]}).to_list(None)}
    assert {
        "RESOLVES_TO",
        "USES_NAMESERVER",
        "BELONGS_TO_ASN",
        "HOSTED_ON",
        "USES_CERTIFICATE",
        "SHARES_FAVICON",
        "REDIRECTS_TO",
        "HAS_URL",
        "SHARES_CERTIFICATE",
        "SHARES_ANALYTICS",
        "SHARES_PIXEL",
    } <= rel_types

    kinds = {a["kind"] for a in await db["artifacts"].find({"investigation_id": doc["_id"]}).to_list(None)}
    assert {"http_response", "html", "headers", "cookies", "redirect_chain", "tls", "favicon", "fingerprints"} <= kinds

    assert inv["summary"]["assets_discovered"] == len(assets)
    assert inv["summary"]["relationships"] >= 9

    messages = []
    while not queue.empty():
        messages.append(queue.get_nowait())
    types = {m["type"] for m in messages}
    assert {"investigation_status", "stage_started", "stage_progress", "stage_event", "stage_completed"} <= types


async def test_cancellation(db, runner, monkeypatch):
    r, _ = runner
    gate = asyncio.Event()

    async def slow_fetch(url: str, **_: object) -> PageFetch:
        await gate.wait()
        return PageFetch(requested_url=url, error="cancelled test")

    monkeypatch.setattr("app.collectors.web.fetch_page", slow_fetch)
    doc = r.new_document("slow.test", InvestigationOptions(screenshots=False), created_by="tester")
    await r.submit(doc)
    await asyncio.sleep(0.3)
    assert await r.cancel(doc["_id"])
    gate.set()
    await r.wait(doc["_id"], timeout=30)
    inv = await db["investigations"].find_one({"_id": doc["_id"]})
    assert inv["status"] == "cancelled"


async def test_certificate_ioc_skips_web_collection(db, runner):
    r, _ = runner
    doc = r.new_document("a" * 64, InvestigationOptions(screenshots=False), created_by="tester")
    await r.submit(doc)
    await r.wait(doc["_id"], timeout=30)
    inv = await db["investigations"].find_one({"_id": doc["_id"]})
    assert inv["status"] == "completed"
    root = await db["assets"].find_one({"_id": inv["root_asset_id"]})
    assert root["type"] == "certificate"


async def test_recover_requeues_interrupted(db, runner, offline_collectors):
    r, _ = runner
    doc = r.new_document("phish.test", InvestigationOptions(screenshots=False), created_by="tester")
    doc["status"] = "running"
    await db["investigations"].insert_one(doc)
    assert await r.recover() == 1
    await r.wait(doc["_id"], timeout=30)
    assert (await db["investigations"].find_one({"_id": doc["_id"]}))["status"] == "completed"


async def test_full_four_stage_pipeline_pivots_correlates_and_clusters(db, offline_collectors, monkeypatch):
    """Seed knowledge from an earlier investigation is found by pivots, scored and clustered."""
    from app.pipeline.stages.correlation import CorrelationStage
    from app.pipeline.stages.pivot import PivotStage
    from app.repositories.assets import AssetRepository

    original_fetch = __import__("app.collectors.web", fromlist=["fetch_page"]).fetch_page

    async def selective_fetch(url: str, **kw: object) -> PageFetch:
        if "phish.test" in url:
            return await original_fetch(url, **kw)
        return PageFetch(requested_url=url, error="request failed: Connection refused")

    monkeypatch.setattr("app.collectors.web.fetch_page", selective_fetch)

    # Knowledge from a previous investigation: a sister site reusing the same GA4 ID and favicon.
    favicon_hash = __import__("app.fingerprints.images", fromlist=["favicon_mmh3"]).favicon_mmh3(png_bytes())
    await AssetRepository(db).upsert(
        "domain",
        "contoso-account-verify.test",
        source="earlier",
        fingerprints={
            "analytics_ids": ["G-ABC123XYZ9"],
            "tracking_ids": ["G-ABC123XYZ9"],
            "favicon_mmh3": favicon_hash,
        },
        attributes={"web": {"status_code": 200}},
        extra={"status": "ACTIVE"},
    )

    providers = {p.name: p for p in (FakeDNS(), FakeCymru(), FakeCT())}
    pm = ProviderManager(db, providers=providers)
    await pm.startup()
    runner = PipelineRunner(
        db, pm, ProgressHub(), stages=[CollectionStage(), EnrichmentStage(), PivotStage(), CorrelationStage()]
    )
    doc = runner.new_document(
        "phish.test",
        InvestigationOptions(screenshots=False, credit_policy="never", brand="Contoso", max_pivot_assets=3),
        created_by="tester",
    )
    await runner.submit(doc)
    await runner.wait(doc["_id"], timeout=60)
    await runner.shutdown()
    await pm.shutdown()

    inv = await db["investigations"].find_one({"_id": doc["_id"]})
    assert inv["status"] == "completed", inv.get("error")
    for stage in ("collection", "enrichment", "pivot", "correlation"):
        assert inv["stages"][stage]["status"] == "completed", (stage, inv["stages"][stage])

    sister = await db["assets"].find_one({"value": "contoso-account-verify.test"})
    assert doc["_id"] in sister["investigation_ids"]  # pulled in by local pivots
    corr = sister["correlation"][doc["_id"]]
    features = {m["feature"] for m in corr["matches"]}
    assert {"analytics", "favicon"} <= features
    assert corr["score"] >= 70 and sister["confidence"] >= 70

    relationships = await db["relationships"].find({"source": sister["_id"]}).to_list(None)
    assert {"SHARES_ANALYTICS", "SHARES_FAVICON"} <= {r["type"] for r in relationships}

    assert inv["cluster_ids"], "a cluster should have been formed"
    cluster = await db["clusters"].find_one({"_id": inv["cluster_ids"][0]})
    assert "contoso-account-verify.test" in cluster["domains"]
    assert cluster["name"] == "Contoso impersonation cluster"
    assert inv["summary"]["clusters"] == 1
    assert inv["summary"]["high_confidence"] >= 2
    assert inv["summary"]["max_confidence"] == 100
