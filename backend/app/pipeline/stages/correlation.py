"""STEP 4 - Correlation and clustering."""

from __future__ import annotations

from typing import Any

from app.analysis.correlation import correlate
from app.graph.builder import load_graph_for_investigation
from app.models.common import utcnow
from app.models.investigation import StageName
from app.pipeline.context import InvestigationContext
from app.pipeline.stages.base import Stage
from app.services.clusters import ClusterEngine
from app.services.scoring_config import get_scoring

S = StageName.CORRELATION.value


class CorrelationStage(Stage):
    name = StageName.CORRELATION

    async def run(self, ctx: InvestigationContext) -> str | None:
        config = await get_scoring(ctx.db)
        await ctx.progress(S, 10, "Building investigation graph")
        g = await load_graph_for_investigation(ctx.db, ctx.id, max_nodes=5000)
        seeds: list[str] = list(ctx.state.get("seed_ids") or [])
        if not seeds:
            profile = ctx.state.get("web_profile")
            for doc in (ctx.state.get("host_asset"), profile.final_host_asset if profile else None, ctx.root_asset):
                if doc and doc["_id"] not in seeds:
                    seeds.append(doc["_id"])
            seeds = seeds[:2]
        host_ids = [n for n, d in g.nodes(data=True) if d.get("type") in ("domain", "ip")]
        assets = {
            a["_id"]: a
            for a in await ctx.db["assets"]
            .find({"_id": {"$in": host_ids}}, {"fingerprints": 1, "type": 1, "value": 1})
            .to_list(length=len(host_ids) or 1)
        }

        noisy_cache: dict[str, bool] = {}

        limit = config.noisy_fingerprint_limit

        async def prefetch_noise() -> None:
            fp_nodes = [n for n, d in g.nodes(data=True) if d.get("type") not in ("domain", "url", "cluster")]
            if not fp_nodes:
                return
            pipeline: list[dict[str, Any]] = [
                {"$match": {"target": {"$in": fp_nodes}}},
                {"$group": {"_id": "$target", "n": {"$sum": 1}}},
            ]
            async for row in ctx.db["relationships"].aggregate(pipeline):
                noisy_cache[row["_id"]] = row["n"] > limit

        await prefetch_noise()
        await ctx.progress(S, 30, f"Scoring {len(host_ids)} host(s) against {len(seeds)} seed(s)")
        results = correlate(g, seeds, assets, config, noise=lambda n: noisy_cache.get(n, False))

        now = utcnow()
        high = 0
        for r in results:
            level = config.thresholds.level(r.score).value
            current = await ctx.db["assets"].find_one({"_id": r.asset_id}, {"confidence": 1})
            best = max(r.score, int((current or {}).get("confidence") or 0))
            await ctx.assets.raw_update(
                r.asset_id,
                {
                    "$set": {
                        "confidence": best,
                        "confidence_level": config.thresholds.level(best).value,
                        f"correlation.{ctx.id}": {
                            "score": r.score,
                            "level": level,
                            "matches": r.matches,
                            "computed_at": now,
                        },
                    }
                },
            )
            if r.score >= config.thresholds.high:
                high += 1
            # URLs owned by a scored host inherit its score for display/filtering.
            for _, url_node, data in g.out_edges(r.asset_id, data=True):
                if data.get("type") == "HAS_URL":
                    await ctx.assets.raw_update(url_node, {"$max": {"confidence": r.score}})
        await ctx.progress(S, 70, f"{high} high-confidence asset(s); building threat clusters")

        root_value = (ctx.state.get("host_asset") or ctx.root_asset or {}).get("value", ctx.ioc.value)
        cluster = await ClusterEngine(ctx.db).build_for_investigation(
            ctx.id,
            results,
            g,
            config,
            root_value=root_value,
            brand=ctx.options.brand,
        )
        if cluster:
            await ctx.log(
                S,
                f"Cluster {cluster['_id']} '{cluster['name']}': {len(cluster['asset_ids'])} member(s), "
                f"confidence {cluster['confidence']} ({cluster['confidence_level']})",
            )
            await ctx.investigations.raw_update(ctx.id, {"$addToSet": {"cluster_ids": cluster["_id"]}})
            ctx.state["cluster"] = cluster
        else:
            await ctx.log(S, f"No cluster formed (fewer than 2 hosts at confidence >= {config.thresholds.cluster_min})")
        top = sorted((r for r in results if r.asset_id not in seeds), key=lambda r: r.score, reverse=True)[:5]
        for r in top:
            if r.score:
                value = g.nodes[r.asset_id].get("value")
                feats = ", ".join(f"{m['feature']}+{m['weight']:g}" for m in r.matches[:4])
                await ctx.log(S, f"{value}: {r.score} ({config.thresholds.level(r.score).value}) - {feats}")
        await ctx.progress(S, 100)
        return f"Scored {len(results)} host(s); {high} high confidence; " + (
            f"cluster {cluster['_id']}" if cluster else "no cluster"
        )
