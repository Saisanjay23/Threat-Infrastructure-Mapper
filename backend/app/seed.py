"""Realistic demo dataset: 10 phishing/fraud operations against fictional brands.

* 100 domains (80 in operations, 20 unrelated/benign noise)
* 30 IP addresses (documentation ranges 192.0.2/24, 198.51.100/24, 203.0.113/24)
* 15 TLS certificates, shared analytics / GTM / pixel IDs, favicons, nameservers, ASNs (AS64496-AS64511)
* synthetic screenshots, one completed investigation per operation
* clusters, confidence scores and the graph are produced by the real correlation + cluster engines

All seeded documents carry `seed: true` so `python -m app.cli seed --reset` can remove them safely.
Only reserved names are used (.test / .example TLDs, documentation IP ranges and ASNs).
"""

from __future__ import annotations

import hashlib
import io
import logging
import random
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from app.analysis.brand import assess_brand
from app.analysis.content import classify_content
from app.analysis.correlation import correlate
from app.db.mongo import Collections, Mongo
from app.fingerprints.images import image_fingerprints, perceptual_hashes
from app.fingerprints.website import extract_website_fingerprints
from app.graph.builder import load_graph_for_investigation
from app.models.common import new_id, utcnow
from app.models.investigation import STAGE_ORDER
from app.pipeline.runner import compute_investigation_summary
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository, asset_id
from app.repositories.relationships import RelationshipRepository, edge_id
from app.services.bootstrap import ensure_admin
from app.services.clusters import ClusterEngine
from app.services.scoring_config import get_scoring

log = logging.getLogger(__name__)
RNG = random.Random(20261001)


@dataclass
class Operation:
    brand: str
    legit: str
    color: tuple[int, int, int]
    words: list[str]
    tld: str
    status_mix: list[str]


OPERATIONS = [
    Operation(
        "Contoso Bank",
        "contoso.com",
        (0, 92, 169),
        ["secure", "login", "verify", "account", "online", "auth", "portal", "update"],
        "test",
        ["ACTIVE"] * 5 + ["TAKEDOWN", "PARKED", "INACTIVE"],
    ),
    Operation(
        "Fabrikam Pay",
        "fabrikam.com",
        (102, 45, 145),
        ["pay", "wallet", "billing", "confirm", "secure", "reset", "help", "id"],
        "test",
        ["ACTIVE"] * 6 + ["TAKEDOWN", "TAKEDOWN"],
    ),
    Operation(
        "Northwind Logistics",
        "northwind.com",
        (0, 128, 96),
        ["track", "parcel", "delivery", "customs", "redeliver", "fee", "shipment", "notice"],
        "example",
        ["ACTIVE"] * 4 + ["PARKED", "INACTIVE", "TAKEDOWN", "ACTIVE"],
    ),
    Operation(
        "Woodgrove Wallet",
        "woodgrovebank.com",
        (200, 120, 0),
        ["wallet", "connect", "claim", "airdrop", "sync", "restore", "seed", "verify"],
        "test",
        ["ACTIVE"] * 7 + ["INACTIVE"],
    ),
    Operation(
        "Tailspin Air",
        "tailspintoys.com",
        (220, 50, 47),
        ["miles", "rewards", "checkin", "booking", "refund", "member", "login", "support"],
        "example",
        ["ACTIVE"] * 5 + ["PARKED"] * 2 + ["TAKEDOWN"],
    ),
    Operation(
        "Litware Mail",
        "litwareinc.com",
        (32, 120, 200),
        ["webmail", "mailbox", "quota", "sso", "office", "verify", "portal", "secure"],
        "test",
        ["ACTIVE"] * 6 + ["TAKEDOWN", "INACTIVE"],
    ),
    Operation(
        "Adventure Works Shop",
        "adventure-works.com",
        (180, 60, 120),
        ["shop", "outlet", "sale", "store", "deals", "order", "checkout", "promo"],
        "example",
        ["ACTIVE"] * 4 + ["PARKED"] * 3 + ["ACTIVE"],
    ),
    Operation(
        "Proseware Cloud",
        "proseware.com",
        (60, 60, 180),
        ["cloud", "drive", "share", "files", "docs", "login", "secure", "sync"],
        "test",
        ["ACTIVE"] * 6 + ["TAKEDOWN", "PARKED"],
    ),
    Operation(
        "Wingtip Telecom",
        "wingtiptoys.com",
        (0, 150, 200),
        ["mobile", "bill", "topup", "support", "account", "recharge", "esim", "verify"],
        "example",
        ["ACTIVE"] * 5 + ["INACTIVE", "TAKEDOWN", "ACTIVE"],
    ),
    Operation(
        "Fourth Coffee Rewards",
        "fourthcoffee.com",
        (120, 72, 40),
        ["rewards", "points", "giftcard", "survey", "claim", "member", "offer", "bonus"],
        "test",
        ["ACTIVE"] * 4 + ["PARKED", "PARKED", "TAKEDOWN", "ACTIVE"],
    ),
]
NOISE_DOMAINS = [
    "weather-today.example",
    "recipe-garden.test",
    "city-library.example",
    "bike-trails.test",
    "garden-tools.example",
    "local-news-daily.test",
    "chess-club.example",
    "photo-gallery.test",
    "hiking-guide.example",
    "music-school.test",
    "tech-blog-notes.example",
    "travel-diary.test",
    "pet-adoption.example",
    "language-lab.test",
    "astro-photos.example",
    "home-repair.test",
    "yoga-studio.example",
    "board-games.test",
    "vintage-cars.example",
    "coffee-roasters.test",
]
REGISTRARS = ["Example Registrar LLC", "Sample Domains Inc.", "Reserved Names Ltd", "Demo Registry Services"]
HOSTING = [
    ("AS64496", "Bulletproof Example Hosting"),
    ("AS64497", "Offshore VPS Example"),
    ("AS64498", "Budget Cloud Example"),
    ("AS64499", "Shared Hosting Example"),
    ("AS64500", "Example CDN Network"),
    ("AS64501", "Residential Proxy Example"),
]


def _ip_pool() -> list[str]:
    pool = (
        [f"192.0.2.{i}" for i in range(10, 20)]
        + [f"198.51.100.{i}" for i in range(20, 30)]
        + [f"203.0.113.{i}" for i in range(30, 40)]
    )
    return pool  # 30 IPs


def _tracker(prefix: str, n: int) -> str:
    h = hashlib.sha256(f"{prefix}{n}".encode()).hexdigest().upper()
    if prefix == "G-":
        return "G-" + h[:10]
    if prefix == "UA-":
        return f"UA-{int(h[:7], 16) % 9000000 + 1000000}-1"
    if prefix == "GTM-":
        return "GTM-" + h[:7]
    return str(int(h[:15], 16))[:15]  # meta pixel


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in ("segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def fake_screenshot(
    brand: str, domain: str, color: tuple[int, int, int], status: str, variant: int, varied: bool = False
) -> bytes:
    img = Image.new("RGB", (1280, 720), (245, 247, 250) if not varied else (30 + variant * 25, 35, 45))
    d = ImageDraw.Draw(img)
    if status == "PARKED":
        d.rectangle((0, 0, 1280, 720), fill=(250, 250, 250))
        d.text((420, 260), f"{domain}", fill=(40, 40, 40), font=_font(40))
        d.text((420, 330), "This domain may be for sale", fill=(120, 120, 120), font=_font(28))
        d.rectangle((420, 400, 860, 460), fill=(30, 130, 230))
        d.text((520, 412), "Make an offer", fill=(255, 255, 255), font=_font(26))
    elif status == "TAKEDOWN":
        d.rectangle((0, 0, 1280, 720), fill=(255, 255, 255))
        d.text((360, 280), "This account has been suspended.", fill=(180, 30, 30), font=_font(36))
        d.text((360, 340), "Contact your hosting provider for more information.", fill=(90, 90, 90), font=_font(22))
    elif varied:
        x = 120 + (variant % 4) * 180
        d.rectangle((0, 600, 1280, 720), fill=color)
        d.text(
            (x, 80), f"{brand} · {VARIANT_TITLES[variant % len(VARIANT_TITLES)]}", fill=(240, 240, 240), font=_font(30)
        )
        for i in range(variant % 4 + 2):
            d.rectangle((x, 160 + i * 70, x + 520, 210 + i * 70), outline=(200, 200, 200), width=2)
    else:
        d.rectangle((0, 0, 1280, 90), fill=color)
        d.text((60, 24), brand, fill=(255, 255, 255), font=_font(36))
        d.rounded_rectangle((440, 170, 840, 600), radius=18, fill=(255, 255, 255), outline=(220, 224, 230), width=2)
        d.text((480, 200), "Sign in to your account", fill=(30, 30, 30), font=_font(26))
        for i, label in enumerate(("Email or username", "Password")):
            y = 270 + i * 100
            d.text((480, y), label, fill=(100, 100, 100), font=_font(18))
            d.rounded_rectangle((480, y + 28, 800, y + 72), radius=8, outline=(200, 204, 210), width=2)
        d.rounded_rectangle((480, 490, 800, 545), radius=8, fill=color)
        d.text((585, 503), "Verify", fill=(255, 255, 255), font=_font(24))
        d.text((480, 560 + (variant % 3) * 4), f"Secure session · {domain}", fill=(150, 150, 150), font=_font(14))
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue()


def favicon_png(color: tuple[int, int, int], letter: str) -> bytes:
    img = Image.new("RGB", (32, 32), color)
    ImageDraw.Draw(img).text((9, 6), letter, fill=(255, 255, 255), font=_font(18))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def thumbnail(png: bytes) -> bytes:
    with Image.open(io.BytesIO(png)) as src:
        img = src.convert("RGB")
        img.thumbnail((480, 270))
        out = io.BytesIO()
        img.save(out, format="JPEG", quality=80)
        return out.getvalue()


VARIANT_TITLES = ["Customer Portal", "Account Center", "Secure Access", "Member Login", "Help Desk", "Verification"]


def phish_html(op: Operation, domain: str, trackers: dict[str, str], status: str, variant: int | None = None) -> str:
    if status == "PARKED":
        return (
            f"<html><head><title>{domain}</title></head><body><h1>{domain}</h1><p>This domain may be for sale. "
            "Buy this domain today. Related searches.</p></body></html>"
        )
    if status == "TAKEDOWN":
        return (
            "<html><head><title>Account Suspended</title></head><body><h1>This account has been suspended.</h1>"
            "<p>Contact your hosting provider for more information.</p></body></html>"
        )
    if status == "INACTIVE":
        return (
            "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested URL was "
            "not found on this server.</p></body></html>"
        )
    if variant is not None:
        # Rotating kit variants: different titles and page structure per domain.
        title = f"{VARIANT_TITLES[variant % len(VARIANT_TITLES)]} | {op.brand}"
        blocks = "".join(
            f"<section class='b{i}'><div><h3>Notice {i}</h3><ul>" + "<li>item</li>" * (i + 1) + "</ul></div></section>"
            for i in range(variant % 4 + 1)
        )
        return f"""<!doctype html><html><head><title>{title}</title>
<script>(function(w,d,s,l,i){{}})(window,document,'script','dataLayer','{trackers["gtm"]}');</script>
<script>fbq('init', '{trackers["pixel"]}');</script></head><body><nav><a>Home</a><a>Help</a></nav>{blocks}
<table><tr><td><form method="post" action="/{op.words[variant % 8]}.php"><input name="user"><input type="password" name="pw">
<input type="submit" value="Continue"></form></td></tr></table><footer>{op.brand} {variant}</footer></body></html>"""
    return f"""<!doctype html><html lang="en"><head><title>{op.brand} - Secure Login</title>
<meta name="description" content="Sign in to your {op.brand} account">
<script async src="https://www.googletagmanager.com/gtag/js?id={trackers["ga4"]}"></script>
<script>gtag('config', '{trackers["ga4"]}'); gtag('config', '{trackers["ua"]}');</script>
<script>(function(w,d,s,l,i){{}})(window,document,'script','dataLayer','{trackers["gtm"]}');</script>
<script>fbq('init', '{trackers["pixel"]}');</script>
<link rel="icon" href="/favicon.png"></head><body><header><img src="/assets/logo.png" alt="{op.brand} logo"></header>
<main class="login"><h2>Sign in to your account</h2><form action="https://collect-{op.words[0]}.example/post.php" method="post">
<input type="email" name="email" placeholder="Email or username"><input type="password" name="password">
<button>Verify</button></form><p>Need help? Contact {op.brand} support to update or reset your account.</p></main></body></html>"""


async def reset_seed(db: Any, fs: Any) -> dict[str, int]:
    removed: dict[str, int] = {}
    seeded_inv = [d["_id"] async for d in db[Collections.INVESTIGATIONS].find({"seed": True}, {"_id": 1})]
    seeded_clusters = (
        [d["_id"] async for d in db[Collections.CLUSTERS].find({"investigation_ids": {"$in": seeded_inv}}, {"_id": 1})]
        if seeded_inv
        else []
    )
    for name, query in (
        (Collections.INVESTIGATIONS, {"seed": True}),
        (Collections.ASSETS, {"$or": [{"seed": True}, {"type": "cluster", "value": {"$in": seeded_clusters}}]}),
        (Collections.RELATIONSHIPS, {"seed": True}),
        (Collections.CLUSTERS, {"_id": {"$in": seeded_clusters}}),
        (Collections.ARTIFACTS, {"metadata.seed": True}),
    ):
        removed[name] = (await db[name].delete_many(query)).deleted_count
    await db[Collections.RELATIONSHIPS].delete_many({"investigation_ids": {"$in": seeded_inv}})
    files = db["files.files"]
    async for f in files.find({"metadata.seed": True}, {"_id": 1}):
        await fs.delete(f["_id"])
    return removed


async def run_seed(reset: bool = False) -> int:
    """CLI entry point: connect, seed, disconnect."""
    db = await Mongo.connect()
    try:
        await ensure_admin(db)
        await seed_database(db, Mongo.get_fs(), reset=reset)
    finally:
        await Mongo.close()
    return 0


async def seed_database(db: Any, fs: Any, *, reset: bool = False) -> dict[str, int]:
    """Load the demo dataset into `db`. Returns counts; idempotent unless `reset`."""
    if reset:
        print("Removing previous demo data:", await reset_seed(db, fs))
    elif await db[Collections.INVESTIGATIONS].count_documents({"seed": True}):
        print("Demo data already present (use --reset to reload).")
        return {}

    assets = AssetRepository(db)
    rels = RelationshipRepository(db)
    artifacts = ArtifactRepository(db, fs)
    ips = _ip_pool()
    RNG.shuffle(ips)
    now = utcnow()
    config = await get_scoring(db)
    totals_domains = 0
    totals_certs = 0
    totals_ips: set[str] = set()

    async def link(source: str, target: str, rel: str, inv: str, provider: str = "seed", **evidence: Any) -> None:
        await rels.upsert(source, target, rel, investigation_id=inv, provider=provider, evidence=evidence or None)
        await db[Collections.RELATIONSHIPS].update_one({"_id": edge_id(source, target, rel)}, {"$set": {"seed": True}})

    async def node(asset_type: str, value: str, inv: str, **kw: Any) -> dict[str, Any]:
        doc = await assets.upsert(asset_type, value, investigation_id=inv, source=kw.pop("source", "seed"), **kw)
        await db[Collections.ASSETS].update_one({"_id": doc["_id"]}, {"$set": {"seed": True}})
        return doc

    for index, op in enumerate(OPERATIONS):
        inv_id = new_id("inv_")
        created = now - timedelta(days=13 - index, hours=RNG.randint(0, 20))
        slug = op.brand.split()[0].lower()
        domains = [f"{slug}-{w}.{op.tld}" if i % 2 == 0 else f"{w}-{slug}.{op.tld}" for i, w in enumerate(op.words)]
        trackers = {
            "ga4": _tracker("G-", index),
            "ua": _tracker("UA-", index),
            "gtm": _tracker("GTM-", index),
            "pixel": _tracker("PX", index),
        }
        op_ips = ips[index * 3 : index * 3 + 3]
        asn, hosting = HOSTING[index % len(HOSTING)]
        ns = [f"ns1.{slug}-dns.{op.tld}", f"ns2.{slug}-dns.{op.tld}"]
        favicon = favicon_png(op.color, op.brand[0])
        fav_fp = image_fingerprints(favicon)
        fav_art = await artifacts.store_file(
            "favicon",
            favicon,
            filename="favicon.png",
            content_type="image/png",
            investigation_id=inv_id,
            metadata={"seed": True},
        )
        # 15 certificates: the first five operations split their domains across two certificates.
        cert_groups = [domains[: len(domains) // 2], domains[len(domains) // 2 :]] if index < 5 else [domains]

        root_dom = domains[0]
        fav_node = await node(
            "favicon",
            fav_fp["mmh3"],
            inv_id,
            attributes={
                "md5": fav_fp["md5"],
                "sha256": fav_fp["sha256"],
                "file_id": fav_art["file_id"],
                "phash": fav_fp.get("phash"),
            },
            fingerprints={"favicon_mmh3": fav_fp["mmh3"], "favicon_phash": fav_fp.get("phash")},
        )
        tracker_nodes = {
            "ga4": await node("analytics", trackers["ga4"], inv_id, attributes={"family": "ga4"}),
            "ua": await node("analytics", trackers["ua"], inv_id, attributes={"family": "google_analytics"}),
            "gtm": await node("tracking", trackers["gtm"], inv_id, attributes={"family": "gtm"}),
            "pixel": await node("pixel", trackers["pixel"], inv_id, attributes={"family": "meta_pixel"}),
        }
        asn_node = await node("asn", asn, inv_id, attributes={"as_name": hosting})
        host_node = await node("hosting", hosting, inv_id)
        ns_nodes = [await node("nameserver", n, inv_id) for n in ns]
        ip_nodes = []
        for ip in op_ips:
            totals_ips.add(ip)
            ipn = await node(
                "ip",
                ip,
                inv_id,
                attributes={"network": {"asn": asn, "as_name": hosting, "country": "ZZ", "hosting_provider": hosting}},
                fingerprints={"asn": asn, "hosting": hosting},
                extra={"status": "ACTIVE"},
            )
            await link(ipn["_id"], asn_node["_id"], "BELONGS_TO_ASN", inv_id)
            await link(ipn["_id"], host_node["_id"], "HOSTED_ON", inv_id)
            ip_nodes.append(ipn)
        cert_nodes = []
        for g_index, group in enumerate(cert_groups):
            sha = hashlib.sha256(f"seed-cert-{index}-{g_index}".encode()).hexdigest()
            cert_nodes.append(
                (
                    group,
                    await node(
                        "certificate",
                        sha,
                        inv_id,
                        attributes={
                            "issuer_org": "Example Free CA",
                            "subject_cn": group[0],
                            "san": group,
                            "validity_days": 90,
                            "not_before": (created - timedelta(days=5)).isoformat(),
                            "not_after": (created + timedelta(days=85)).isoformat(),
                            "trusted": True,
                        },
                        fingerprints={"cert_sha256": sha},
                    ),
                )
            )
            totals_certs += 1

        for d_index, domain in enumerate(domains):
            status = op.status_mix[d_index % len(op.status_mix)]
            varied = index % 4 in (2, 3) and d_index > 0
            html = phish_html(op, domain, trackers, status, d_index if varied else None)
            fp = extract_website_fingerprints(html, f"https://{domain}/")
            verdict = classify_content(
                status_code=200 if status != "INACTIVE" else 404,
                html=html,
                text=fp.get("text_excerpt"),
                title=fp.get("title"),
                word_count=fp.get("word_count"),
                has_login_form=fp.get("has_login_form", False),
            )
            brand = assess_brand(
                domain, fp, brand=op.brand, brand_domains=[op.legit], site_active=verdict.status.value == "ACTIVE"
            )
            shot = fake_screenshot(op.brand, domain, op.color, status, d_index, varied and status == "ACTIVE")
            shot_art = await artifacts.store_file(
                "screenshot_desktop",
                shot,
                filename="desktop.png",
                content_type="image/png",
                investigation_id=inv_id,
                asset_id=asset_id("domain", domain),
                metadata={"seed": True, "url": f"https://{domain}/"},
            )
            thumb_art = await artifacts.store_file(
                "screenshot_thumbnail",
                thumbnail(shot),
                filename="thumbnail.jpg",
                content_type="image/jpeg",
                investigation_id=inv_id,
                asset_id=asset_id("domain", domain),
                metadata={"seed": True, "url": f"https://{domain}/", "final_url": f"https://{domain}/"},
            )
            shot_fp = perceptual_hashes(shot)
            dom_ips = [ip_nodes[d_index % len(ip_nodes)]]
            active = status == "ACTIVE"
            cert_node = next(c for g, c in cert_nodes if domain in g)
            dom_fp: dict[str, Any] = {
                "ips": [n["value"] for n in dom_ips],
                "nameservers": ns,
                "asns": [asn],
                "hosting": [hosting],
                "cert_sha256": cert_node["value"],
                "title_hash": fp.get("title_hash"),
                "title_normalized": fp.get("title_normalized"),
                "html_simhash": fp.get("dom_simhash"),
                "screenshot_phash": shot_fp.get("phash"),
                "screenshot_dhash": shot_fp.get("dhash"),
                "registrar": REGISTRARS[index % len(REGISTRARS)],
            }
            if active:
                dom_fp.update(
                    {
                        "tracking_ids": fp.get("tracking_ids", []),
                        "analytics_ids": sorted([trackers["ga4"], trackers["ua"]]),
                        "gtm_ids": [trackers["gtm"]],
                        "pixel_ids": [trackers["pixel"]],
                        "favicon_mmh3": fav_fp["mmh3"],
                        "favicon_phash": fav_fp.get("phash"),
                    }
                )
            dnode = await node(
                "domain",
                domain,
                inv_id,
                attributes={
                    "title": fp.get("title"),
                    "web": {
                        "final_url": f"https://{domain}/",
                        "status_code": 404 if status == "INACTIVE" else 200,
                        "title": fp.get("title"),
                        "server": "nginx",
                        "ip": dom_ips[0]["value"],
                        "redirect_count": 0,
                    },
                    "infrastructure": {
                        "ips": [n["value"] for n in dom_ips],
                        "nameservers": ns,
                        "asns": [asn],
                        "hosting_providers": [hosting],
                        "registrar": REGISTRARS[index % len(REGISTRARS)],
                        "created": (created - timedelta(days=RNG.randint(1, 20))).isoformat(),
                        "country": "ZZ",
                    },
                    "screenshots": {"desktop": shot_art["file_id"], "thumbnail": thumb_art["file_id"]},
                    "content": verdict.to_dict(),
                    "brand": brand.to_dict(),
                    "website": {
                        "title": fp.get("title"),
                        "has_login_form": fp.get("has_login_form"),
                        "password_fields": fp.get("password_fields"),
                        "tracking_ids": fp.get("tracking_ids"),
                        "trackers": fp.get("trackers"),
                        "external_form_actions": fp.get("external_form_actions"),
                        "form_count": fp.get("form_count"),
                        "word_count": fp.get("word_count"),
                    },
                    **({"favicon": {"file_id": fav_art["file_id"], "mmh3": fav_fp["mmh3"]}} if active else {}),
                    "tls": {"issuer_org": "Example Free CA", "trusted": True, "sha256": cert_node["value"]},
                },
                fingerprints=dom_fp,
                extra={
                    "status": verdict.status.value,
                    "impersonation_score": brand.impersonation_score,
                    "brand_similarity_score": brand.brand_similarity_score,
                    **({"is_root": True} if domain == root_dom else {}),
                },
            )
            totals_domains += 1
            for ipn in dom_ips:
                await link(dnode["_id"], ipn["_id"], "RESOLVES_TO", inv_id, record="A")
            for nsn in ns_nodes:
                await link(dnode["_id"], nsn["_id"], "USES_NAMESERVER", inv_id)
            await link(dnode["_id"], cert_node["_id"], "USES_CERTIFICATE", inv_id, port=443)
            # Operators reuse different artefacts; this spreads cluster confidence across levels.
            profile = index % 4
            if active:
                if profile in (0, 2) or d_index % 3 == 0:
                    await link(dnode["_id"], fav_node["_id"], "SHARES_FAVICON", inv_id)
                if profile == 0 or (profile == 1 and d_index % 2 == 0):
                    await link(dnode["_id"], tracker_nodes["ga4"]["_id"], "SHARES_ANALYTICS", inv_id)
                    await link(dnode["_id"], tracker_nodes["ua"]["_id"], "SHARES_ANALYTICS", inv_id)
                if profile in (0, 1) and d_index % 3 != 2:
                    await link(dnode["_id"], tracker_nodes["gtm"]["_id"], "SHARES_TRACKING", inv_id)
                if profile == 3 or (profile == 0 and d_index % 2 == 0):
                    await link(dnode["_id"], tracker_nodes["pixel"]["_id"], "SHARES_PIXEL", inv_id)

        # Noise: two unrelated domains co-hosted on the operation's shared infrastructure.
        for noise in NOISE_DOMAINS[index * 2 : index * 2 + 2]:
            ipn = ip_nodes[-1]
            nn = await node(
                "domain",
                noise,
                inv_id,
                attributes={
                    "title": noise.split(".")[0].replace("-", " ").title(),
                    "web": {"final_url": f"https://{noise}/", "status_code": 200, "title": noise.split(".")[0].title()},
                },
                fingerprints={
                    "ips": [ipn["value"]],
                    "asns": [asn],
                    "hosting": [hosting],
                    "title_normalized": noise.split(".")[0].replace("-", " "),
                },
                extra={"status": "ACTIVE", "impersonation_score": 0},
            )
            await link(nn["_id"], ipn["_id"], "RESOLVES_TO", inv_id, record="A")
            totals_domains += 1

        root = await db[Collections.ASSETS].find_one({"_id": asset_id("domain", root_dom)})
        stages = {
            s.value: {
                "status": "completed",
                "progress": 100,
                "message": "seeded",
                "started_at": created,
                "finished_at": created + timedelta(seconds=30 + 20 * i),
                "events": [
                    {
                        "timestamp": created + timedelta(seconds=5 * i),
                        "level": "info",
                        "message": f"{s.value} completed (demo data)",
                    }
                ],
            }
            for i, s in enumerate(STAGE_ORDER)
        }
        await db[Collections.INVESTIGATIONS].insert_one(
            {
                "_id": inv_id,
                "ioc": root_dom,
                "ioc_type": "domain",
                "normalized": root_dom,
                "status": "completed",
                "options": {
                    "screenshots": True,
                    "credit_policy": "never",
                    "expand_pivots": True,
                    "max_pivot_assets": 15,
                    "brand": op.brand,
                    "brand_domains": [op.legit],
                    "providers": None,
                    "notes": None,
                },
                "stages": stages,
                "summary": {},
                "root_asset_id": root["_id"] if root else None,
                "tags": ["demo", slug],
                "case_id": None,
                "bulk_id": None,
                "created_by": "admin",
                "created_at": created,
                "updated_at": created,
                "started_at": created,
                "finished_at": created + timedelta(minutes=2),
                "error": None,
                "notes": [
                    {
                        "id": new_id("note_"),
                        "text": f"Demo operation impersonating {op.brand}.",
                        "author": "admin",
                        "created_at": created,
                    }
                ],
                "provider_runs": [],
                "seed": True,
            }
        )

        # Run the real correlation + cluster engines over the seeded graph.
        g = await load_graph_for_investigation(db, inv_id)
        host_ids = [n for n, d in g.nodes(data=True) if d.get("type") in ("domain", "ip")]
        docs = {a["_id"]: a for a in await db[Collections.ASSETS].find({"_id": {"$in": host_ids}}).to_list(length=None)}
        results = correlate(g, [root["_id"]], docs, config)
        for r in results:
            await db[Collections.ASSETS].update_one(
                {"_id": r.asset_id},
                {
                    "$set": {
                        "confidence": r.score,
                        "confidence_level": config.thresholds.level(r.score).value,
                        f"correlation.{inv_id}": {
                            "score": r.score,
                            "level": config.thresholds.level(r.score).value,
                            "matches": r.matches,
                            "computed_at": now,
                        },
                    }
                },
            )
        cluster = await ClusterEngine(db).build_for_investigation(
            inv_id, results, g, config, root_value=root_dom, brand=op.brand
        )
        if cluster:
            await db[Collections.INVESTIGATIONS].update_one(
                {"_id": inv_id}, {"$set": {"cluster_ids": [cluster["_id"]]}}
            )
            await db[Collections.CLUSTERS].update_one(
                {"_id": cluster["_id"]}, {"$set": {"created_at": created, "tags": ["demo", slug]}}
            )
        summary = await compute_investigation_summary(db, inv_id)
        await db[Collections.INVESTIGATIONS].update_one({"_id": inv_id}, {"$set": {"summary": summary}})
        print(
            f"  {op.brand:<24} {len(domains)} domains - cluster {cluster['_id'] if cluster else '-'}"
            f" - confidence {cluster['confidence'] if cluster else '-'}"
        )

    n_clusters = await db[Collections.CLUSTERS].count_documents({"tags": "demo"})
    print(
        f"Seeded {totals_domains} domains, {len(totals_ips)} IPs, {totals_certs} certificates, {n_clusters} clusters."
    )
    return {
        "domains": totals_domains,
        "ips": len(totals_ips),
        "certificates": totals_certs,
        "clusters": n_clusters,
    }
