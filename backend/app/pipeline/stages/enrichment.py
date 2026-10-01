"""STEP 2 - Enrichment: CT logs, history, reputation; credit sources according to policy."""

from __future__ import annotations

from app.models.common import AssetType, IOCType
from app.models.investigation import StageName
from app.pipeline.context import InvestigationContext
from app.pipeline.stages.base import Stage
from app.pipeline.stages.collection import CORE_DOMAIN_PROVIDERS, CORE_IP_PROVIDERS
from app.providers.manager import ProviderRun
from app.repositories.base import Doc
from app.utils.ioc import ParsedIOC, is_public_ip, parse_ioc

S = StageName.ENRICHMENT.value
CORE = set(CORE_DOMAIN_PROVIDERS) | set(CORE_IP_PROVIDERS)
WHEN_NEEDED_THRESHOLD = 5
MAX_ENRICHED_IPS = 3


class EnrichmentStage(Stage):
    name = StageName.ENRICHMENT

    async def run(self, ctx: InvestigationContext) -> str | None:
        root = ctx.root_asset
        assert root is not None
        host_asset: Doc | None = ctx.state.get("host_asset")
        targets: list[tuple[ParsedIOC, Doc]] = [(ctx.ioc, root)]
        if host_asset is not None and host_asset["_id"] != root["_id"]:
            targets.append((parse_ioc(host_asset["value"]), host_asset))
        ips = [ip for ip in sorted(ctx.state.get("ips", set())) if is_public_ip(ip) and ip != ctx.ioc.value]
        ip_targets: list[tuple[ParsedIOC, Doc]] = []
        for ip in ips[:MAX_ENRICHED_IPS]:
            asset = await ctx.add_asset(AssetType.IP, ip, source="dns")
            if asset:
                ip_targets.append((parse_ioc(ip), asset))

        restrict = ctx.options.providers
        total_related = 0
        free_runs = 0
        await ctx.progress(S, 5, "Querying free intelligence sources")
        all_targets = targets + ip_targets
        for index, (ioc, asset) in enumerate(all_targets):
            ctx.check_cancelled()
            names = await ctx.providers.eligible(ioc.type, category="free", names=restrict, exclude=CORE)
            if not names:
                continue
            runs = await ctx.providers.run_many(names, ioc)
            total_related += await self._apply(ctx, runs, asset)
            free_runs += sum(1 for r in runs if r.ok)
            await ctx.progress(S, 5 + int(55 * (index + 1) / len(all_targets)), f"Free sources done for {ioc.value}")

        policy = ctx.options.credit_policy
        discovered = await ctx.assets.count({"investigation_ids": ctx.id, "type": {"$in": ["domain", "ip"]}})
        page = ctx.state.get("page")
        site_unreachable = page is not None and not page.ok
        use_credit = policy == "always" or (
            policy == "when_needed" and (discovered < WHEN_NEEDED_THRESHOLD or site_unreachable)
        )
        if policy == "never":
            await ctx.log(S, "Credit-based sources disabled for this investigation")
        elif not use_credit:
            await ctx.log(S, f"Credit sources not needed ({discovered} infrastructure assets from free sources)")
        else:
            reason = (
                "policy=always"
                if policy == "always"
                else ("site unreachable" if site_unreachable else f"only {discovered} assets from free sources")
            )
            await ctx.log(S, f"Querying credit-based sources ({reason})")
            credit_targets = targets + ip_targets[:1] if ctx.ioc.type != IOCType.IP else targets
            for index, (ioc, asset) in enumerate(credit_targets):
                ctx.check_cancelled()
                names = await ctx.providers.eligible(ioc.type, category="credit", names=restrict)
                if not names:
                    continue
                runs = await ctx.providers.run_many(names, ioc, concurrency=3)
                total_related += await self._apply(ctx, runs, asset)
                await ctx.progress(
                    S, 60 + int(35 * (index + 1) / len(credit_targets)), f"Credit sources done for {ioc.value}"
                )
        await ctx.progress(S, 100)
        return f"{free_runs} free source result(s); {total_related} related entities"

    async def _apply(self, ctx: InvestigationContext, runs: list[ProviderRun], asset: Doc) -> int:
        count = 0
        for run in runs:
            await ctx.record_provider_run(run, asset, S)
            if run.ok:
                n = await ctx.apply_related(asset, run.result.related, run.provider)
                count += n
                await ctx.log(S, f"{run.provider} on {asset['value']}: {n} related{' (cached)' if run.cached else ''}")
            elif not run.skipped:
                await ctx.log(S, f"{run.provider} on {asset['value']}: {run.error}", "warning")
        return count
