"""STEP 3 - Pivot engine.

Generates pivots from the seed hosts' fingerprints (certificate, favicon, analytics, pixels, trackers,
IP, ASN, hosting, nameservers, logo/HTML/title/screenshot similarity, historical screenshots/DNS),
queries the local intelligence store and pivot-capable providers, turns every hit into a graph
relationship, then expands the most promising candidates with a lightweight web profile.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.fingerprints.images import hash_similarity
from app.fingerprints.similarity import simhash_similarity
from app.models.common import AssetType, IOCType
from app.models.graph import RelatedEntity, RelationType
from app.models.investigation import StageName
from app.pipeline.context import InvestigationContext
from app.pipeline.stages.base import Stage
from app.pipeline.web_profile import WebProfiler
from app.repositories.base import Doc
from app.services.scoring_config import get_scoring
from app.utils.ioc import is_domain, parse_ioc, registered_domain

log = logging.getLogger(__name__)
S = StageName.PIVOT.value

# Infrastructure / platform domains never worth expanding as "related operation" candidates.
KNOWN_INFRA = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googletagmanager.com",
    "google-analytics.com",
    "cloudflare.com",
    "cloudflare.net",
    "amazonaws.com",
    "cloudfront.net",
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",
    "azure.com",
    "microsoft.com",
    "windows.net",
    "office.com",
    "outlook.com",
    "apple.com",
    "icloud.com",
    "facebook.com",
    "fbcdn.net",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.com",
    "github.io",
    "githubusercontent.com",
    "wordpress.com",
    "shopify.com",
    "wixsite.com",
    "squarespace.com",
    "zendesk.com",
    "gmail.com",
    "yahoo.com",
    "letsencrypt.org",
    "digicert.com",
    "sectigo.com",
    "godaddy.com",
    "domaincontrol.com",
    "awsdns-cn.com",
    "w3.org",
    "schema.org",
}
EXPANSION_SKIP_RELATIONS = {"USES_MX", "CNAME_TO", "USES_NAMESERVER"}
SIMILARITY_SCAN_LIMIT = 4000
LOCAL_PIVOT_LIMIT = 200

# fingerprint field -> (relation from candidate to the fingerprint node, asset type of node)
EXACT_PIVOTS: dict[str, tuple[RelationType, str]] = {
    "cert_sha256": (RelationType.USES_CERTIFICATE, "certificate"),
    "favicon_mmh3": (RelationType.SHARES_FAVICON, "favicon"),
    "analytics_ids": (RelationType.SHARES_ANALYTICS, "analytics"),
    "pixel_ids": (RelationType.SHARES_PIXEL, "pixel"),
    "gtm_ids": (RelationType.SHARES_TRACKING, "tracking"),
    "tracking_ids": (RelationType.SHARES_TRACKING, "tracking"),
    "nameservers": (RelationType.USES_NAMESERVER, "nameserver"),
    "ips": (RelationType.RESOLVES_TO, "ip"),
}


def is_known_infra(domain: str) -> bool:
    return registered_domain(domain) in KNOWN_INFRA


class PivotStage(Stage):
    name = StageName.PIVOT

    async def run(self, ctx: InvestigationContext) -> str | None:
        seeds = await self._seeds(ctx)
        if not seeds:
            return "No web-profiled seed host to pivot from"
        ctx.state["seed_ids"] = [s["_id"] for s in seeds]
        await ctx.progress(S, 5, f"Pivoting from {', '.join(s['value'] for s in seeds)}")
        hits = 0
        hits += await self._local_exact(ctx, seeds)
        ctx.check_cancelled()
        await ctx.progress(S, 20, "Searched local intelligence for shared fingerprints")
        hits += await self._local_similarity(ctx, seeds)
        ctx.check_cancelled()
        await ctx.progress(S, 30, "Compared HTML, title, logo and screenshot similarity")
        hits += await self._provider_pivots(ctx, seeds)
        ctx.check_cancelled()
        await ctx.progress(S, 50, "Provider pivots complete")
        await self._history(ctx, seeds)
        expanded = 0
        if ctx.options.expand_pivots and ctx.options.max_pivot_assets > 0:
            expanded = await self._expand(ctx, seeds)
        await ctx.progress(S, 100)
        return f"{hits} pivot hit(s); expanded {expanded} candidate(s)"

    # ------------------------------------------------------------------ seeds
    async def _seeds(self, ctx: InvestigationContext) -> list[Doc]:
        ids: list[str] = []
        host = ctx.state.get("host_asset")
        if host:
            ids.append(host["_id"])
        profile = ctx.state.get("web_profile")
        if profile is not None and profile.final_host_asset["_id"] not in ids:
            ids.append(profile.final_host_asset["_id"])
        if not ids and ctx.root_asset:
            ids.append(ctx.root_asset["_id"])
        docs = await ctx.db["assets"].find({"_id": {"$in": ids}}).to_list(length=10)
        order = {i: n for n, i in enumerate(ids)}
        return sorted(docs, key=lambda d: order.get(d["_id"], 99))

    # ------------------------------------------------------------------ local pivots (historical knowledge)
    async def _local_exact(self, ctx: InvestigationContext, seeds: list[Doc]) -> int:
        hits = 0
        seed_ids = {s["_id"] for s in seeds}
        for seed in seeds:
            fp = seed.get("fingerprints") or {}
            for field, (relation, node_type) in EXACT_PIVOTS.items():
                values = fp.get(field)
                if not values:
                    continue
                values = values if isinstance(values, list) else [values]
                if field == "tracking_ids":
                    values = [
                        v
                        for v in values
                        if v not in set(fp.get("analytics_ids", []) + fp.get("pixel_ids", []) + fp.get("gtm_ids", []))
                    ]
                for value in values[:20]:
                    query = {
                        f"fingerprints.{field}": value,
                        "_id": {"$nin": list(seed_ids)},
                        "type": {"$in": ["domain", "ip"]},
                    }
                    total = await ctx.db["assets"].count_documents(query)
                    if total == 0:
                        continue
                    if total > LOCAL_PIVOT_LIMIT:
                        await ctx.log(S, f"{field}={value} shared by {total} assets - treated as common infrastructure")
                        continue
                    node = await ctx.add_asset(node_type, value, source="pivot")
                    if node is None:
                        continue
                    matches = (
                        await ctx.db["assets"]
                        .find(query, {"_id": 1, "value": 1, "type": 1})
                        .limit(LOCAL_PIVOT_LIMIT)
                        .to_list(length=LOCAL_PIVOT_LIMIT)
                    )
                    for m in matches:
                        await ctx.assets.raw_update(m["_id"], {"$addToSet": {"investigation_ids": ctx.id}})
                        if node_type == "ip" and m["type"] == "ip":
                            continue
                        await ctx.link(
                            m["_id"],
                            node,
                            relation,
                            provider="pivot:local",
                            evidence={"pivot": field, "value": value, "seed": seed["value"]},
                        )
                        hits += 1
                    await ctx.log(S, f"Local pivot {field}={value}: {len(matches)} asset(s)")
        return hits

    async def _local_similarity(self, ctx: InvestigationContext, seeds: list[Doc]) -> int:
        config = await get_scoring(ctx.db)
        sim = config.similarity
        seed_ids = [s["_id"] for s in seeds]
        hits = 0
        projection = {
            "value": 1,
            "type": 1,
            "fingerprints.html_simhash": 1,
            "fingerprints.screenshot_phash": 1,
            "fingerprints.logo_phashes": 1,
            "fingerprints.title_hash": 1,
        }
        cursor = (
            ctx.db["assets"]
            .find(
                {
                    "_id": {"$nin": seed_ids},
                    "type": "domain",
                    "$or": [
                        {"fingerprints.html_simhash": {"$ne": None}},
                        {"fingerprints.screenshot_phash": {"$ne": None}},
                        {"fingerprints.logo_phashes.0": {"$exists": True}},
                    ],
                },
                projection,
            )
            .sort("last_seen", -1)
            .limit(SIMILARITY_SCAN_LIMIT)
        )
        others = await cursor.to_list(length=SIMILARITY_SCAN_LIMIT)
        for seed in seeds:
            sfp = seed.get("fingerprints") or {}
            for other in others:
                ofp = other.get("fingerprints") or {}
                checks = [
                    (
                        RelationType.SIMILAR_HTML,
                        simhash_similarity(sfp.get("html_simhash"), ofp.get("html_simhash")),
                        sim.html,
                        "html_simhash",
                    ),
                    (
                        RelationType.SIMILAR_SCREENSHOT,
                        hash_similarity(sfp.get("screenshot_phash"), ofp.get("screenshot_phash")),
                        sim.screenshot,
                        "screenshot_phash",
                    ),
                ]
                logos = [
                    hash_similarity(a, b) for a in sfp.get("logo_phashes") or [] for b in ofp.get("logo_phashes") or []
                ]
                checks.append((RelationType.SHARES_LOGO, max(logos, default=0.0), sim.logo, "logo_phash"))
                for relation, score, threshold, field in checks:
                    if score >= threshold:
                        await ctx.assets.raw_update(other["_id"], {"$addToSet": {"investigation_ids": ctx.id}})
                        await ctx.relationships.upsert(
                            seed["_id"],
                            other["_id"],
                            relation.value,
                            investigation_id=ctx.id,
                            provider="pivot:similarity",
                            weight=round(score, 3),
                            evidence={"pivot": field, "similarity": round(score, 3)},
                        )
                        hits += 1
        if hits:
            await ctx.log(S, f"Similarity pivots: {hits} visually/structurally similar asset(s)")
        return hits

    # ------------------------------------------------------------------ provider pivots
    async def _provider_pivots(self, ctx: InvestigationContext, seeds: list[Doc]) -> int:
        policy = ctx.options.credit_policy
        candidates_so_far = await ctx.assets.count({"investigation_ids": ctx.id, "type": "domain"})
        allow_credit = policy == "always" or (policy == "when_needed" and candidates_so_far < 10)
        hits = 0
        jobs: list[tuple[str, str, str, Doc]] = []
        for seed in seeds:
            fp = seed.get("fingerprints") or {}
            pivots: list[tuple[str, Any]] = [
                ("cert_sha256", fp.get("cert_sha256")),
                ("cert_sha1", fp.get("cert_sha1")),
                ("favicon_mmh3", fp.get("favicon_mmh3")),
                ("favicon_sha256", fp.get("favicon_sha256")),
                ("title", (seed.get("attributes") or {}).get("title")),
            ]
            pivots += [("tracking_id", t) for t in (fp.get("tracking_ids") or [])[:5]]
            for kind, value in pivots:
                if not value:
                    continue
                for name in await ctx.providers.eligible_pivots(kind, allow_credit=allow_credit):
                    if ctx.options.providers and name not in ctx.options.providers:
                        continue
                    jobs.append((name, kind, str(value), seed))
        sem = asyncio.Semaphore(4)

        async def run(job: tuple[str, str, str, Doc]) -> int:
            name, kind, value, seed = job
            async with sem:
                result = await ctx.providers.pivot(name, kind, value)
            entry = {**result.to_dict(), "stage": S, "target": f"{kind}={value[:80]}"}
            await ctx.investigations.raw_update(ctx.id, {"$push": {"provider_runs": entry}})
            if not result.ok:
                if not result.skipped:
                    await ctx.log(S, f"{name} pivot {kind}: {result.error}", "warning")
                return 0
            node = await self._pivot_node(ctx, kind, value, seed)
            count = 0
            for entity in result.result.related[:150]:
                if entity.type == "domain" and (not is_domain(entity.value) or is_known_infra(entity.value)):
                    continue
                if entity.value == seed["value"]:
                    continue
                target = node or seed
                await ctx.apply_related(
                    target,
                    [
                        RelatedEntity(
                            type=entity.type,
                            value=entity.value,
                            relation=entity.relation,
                            reverse=True,
                            evidence={**entity.evidence, "pivot": kind, "value": value[:120], "provider": name},
                            attributes=entity.attributes,
                        )
                    ],
                    f"pivot:{name}",
                )
                count += 1
            await ctx.log(S, f"{name} pivot {kind}{' (cached)' if result.cached else ''}: {count} hit(s)")
            return count

        for n in await asyncio.gather(*(run(j) for j in jobs)):
            hits += n
        if not allow_credit and policy != "never":
            await ctx.log(S, "Credit-based pivot sources not needed for this investigation")
        return hits

    async def _pivot_node(self, ctx: InvestigationContext, kind: str, value: str, seed: Doc) -> Doc | None:
        """The fingerprint node pivot hits attach to (so hits connect through the shared artefact)."""
        fp = seed.get("fingerprints") or {}
        if kind in ("cert_sha256", "cert_sha1"):
            return await ctx.assets.find_one({"type": "certificate", "value": fp.get("cert_sha256")})
        if kind in ("favicon_mmh3", "favicon_sha256"):
            return await ctx.assets.find_one({"type": "favicon", "value": fp.get("favicon_mmh3")})
        if kind == "tracking_id":
            return await ctx.assets.find_one({"type": {"$in": ["analytics", "pixel", "tracking"]}, "value": value})
        return None

    # ------------------------------------------------------------------ history
    async def _history(self, ctx: InvestigationContext, seeds: list[Doc]) -> None:
        """Historical screenshots (Wayback, urlscan) and historical DNS gathered during enrichment."""
        for seed in seeds:
            doc = await ctx.assets.get(seed["_id"], {"enrichment": 1}) or {}
            enrichment = doc.get("enrichment") or {}
            timeline: list[dict[str, Any]] = []
            for snap in (enrichment.get("wayback") or {}).get("recent_snapshots", [])[:24]:
                timeline.append(
                    {
                        "source": "wayback",
                        "time": snap.get("timestamp"),
                        "url": snap.get("archive_url"),
                        "screenshot_url": snap.get("screenshot_url"),
                        "status": snap.get("status"),
                    }
                )
            for shot in (enrichment.get("urlscan") or {}).get("historical_screenshots", [])[:30]:
                timeline.append(
                    {
                        "source": "urlscan",
                        "time": shot.get("time"),
                        "url": shot.get("url"),
                        "screenshot_url": shot.get("screenshot"),
                    }
                )
            history_ips = (enrichment.get("urlscan") or {}).get("distinct_ips", [])
            if timeline or history_ips:
                timeline.sort(key=lambda t: t.get("time") or "", reverse=True)
                await ctx.assets.raw_update(
                    seed["_id"],
                    {"$set": {"attributes.history": {"screenshots": timeline, "historical_ips": history_ips}}},
                )
                await ctx.log(
                    S, f"History for {seed['value']}: {len(timeline)} snapshot(s), {len(history_ips)} historical IP(s)"
                )

    # ------------------------------------------------------------------ expansion
    async def _expand(self, ctx: InvestigationContext, seeds: list[Doc]) -> int:
        seed_ids = {s["_id"] for s in seeds}
        edges = await ctx.relationships.for_investigation(ctx.id)
        strength: dict[str, float] = {}
        weights = {
            "SHARES_ANALYTICS": 40,
            "SHARES_PIXEL": 40,
            "SHARES_TRACKING": 35,
            "SHARES_FAVICON": 30,
            "USES_CERTIFICATE": 25,
            "SHARES_CERTIFICATE": 25,
            "SHARES_LOGO": 25,
            "SIMILAR_HTML": 20,
            "SIMILAR_SCREENSHOT": 20,
            "REDIRECTS_TO": 30,
            "SUBDOMAIN_OF": 15,
            "RESOLVES_TO": 8,
            "HISTORICAL_RESOLUTION": 6,
            "OBSERVED_WITH": 5,
        }
        for e in edges:
            if e["type"] in EXPANSION_SKIP_RELATIONS:
                continue
            w = weights.get(e["type"], 2)
            for node in (e["source"], e["target"]):
                if node not in seed_ids:
                    strength[node] = strength.get(node, 0) + w
        if not strength:
            return 0
        docs = (
            await ctx.db["assets"]
            .find(
                {"_id": {"$in": list(strength)}, "type": "domain", "attributes.web": {"$exists": False}},
                {"value": 1, "type": 1},
            )
            .to_list(length=5000)
        )
        candidates = [d for d in docs if not is_known_infra(d["value"])]
        candidates.sort(key=lambda d: strength.get(d["_id"], 0), reverse=True)
        chosen = candidates[: ctx.options.max_pivot_assets]
        if not chosen:
            return 0
        await ctx.log(
            S,
            f"Expanding {len(chosen)} candidate(s): {', '.join(c['value'] for c in chosen[:8])}"
            f"{'...' if len(chosen) > 8 else ''}",
        )
        sem = asyncio.Semaphore(4)
        done = 0

        async def expand(candidate: Doc) -> None:
            nonlocal done
            async with sem:
                ctx.check_cancelled()
                try:
                    await self._quick_infra(ctx, candidate)
                    await WebProfiler(ctx, S, report_progress=False).profile(
                        f"https://{candidate['value']}/",
                        candidate,
                        screenshots=ctx.options.screenshots,
                        retry_http=True,
                        source="pivot",
                    )
                except Exception as exc:
                    log.warning("Expansion of %s failed: %s", candidate["value"], exc)
                    await ctx.log(S, f"Expansion of {candidate['value']} failed: {exc}", "warning")
                done += 1
                await ctx.progress(S, 50 + int(50 * done / len(chosen)), f"Profiled {candidate['value']}")

        await asyncio.gather(*(expand(c) for c in chosen))
        return done

    async def _quick_infra(self, ctx: InvestigationContext, candidate: Doc) -> None:
        names = await ctx.providers.eligible(IOCType.DOMAIN, names=["dns"])
        for run in await ctx.providers.run_many(names, parse_ioc(candidate["value"])):
            await ctx.record_provider_run(run, candidate, S)
            if not run.ok:
                continue
            await ctx.apply_related(candidate, run.result.related, run.provider)
            ips = run.result.summary.get("a", [])[:3]
            await ctx.assets.raw_update(
                candidate["_id"],
                {
                    "$set": {
                        "fingerprints.ips": run.result.summary.get("a", []) + run.result.summary.get("aaaa", []),
                        "fingerprints.nameservers": run.result.summary.get("ns", []),
                    }
                },
            )
            for ip in ips:
                ip_names = await ctx.providers.eligible(IOCType.IP, names=["cymru"])
                ip_asset = await ctx.add_asset(AssetType.IP, ip, source="dns")
                for ip_run in await ctx.providers.run_many(ip_names, parse_ioc(ip)):
                    if ip_run.ok and ip_asset:
                        await ctx.apply_related(ip_asset, ip_run.result.related, ip_run.provider)
                        s = ip_run.result.summary
                        await ctx.assets.raw_update(
                            ip_asset["_id"],
                            {
                                "$set": {
                                    "attributes.network": {
                                        k: s.get(k) for k in ("asn", "as_name", "prefix", "country", "hosting_provider")
                                    },
                                    "fingerprints.asn": s.get("asn"),
                                    "fingerprints.hosting": s.get("hosting_provider"),
                                }
                            },
                        )
