"""STEP 1 - Asset collection: web profile, DNS, WHOIS/RDAP, ASN/hosting for the root IOC."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.models.common import AssetType, IOCType
from app.models.graph import RelationType
from app.models.investigation import StageName
from app.pipeline.context import InvestigationContext
from app.pipeline.stages.base import Stage
from app.pipeline.web_profile import WebProfiler, host_asset_type
from app.repositories.base import Doc
from app.utils.ioc import ParsedIOC, is_public_ip, parse_ioc

log = logging.getLogger(__name__)
S = StageName.COLLECTION.value
CORE_DOMAIN_PROVIDERS = ["dns", "rdap", "whois"]
CORE_IP_PROVIDERS = ["cymru", "rdap", "dns"]
MAX_IPS = 10


class CollectionStage(Stage):
    name = StageName.COLLECTION

    async def run(self, ctx: InvestigationContext) -> str | None:
        ioc = ctx.ioc
        root = await self._create_root(ctx, ioc)
        ctx.root_asset = root
        await ctx.investigations.update(ctx.id, {"root_asset_id": root["_id"]})
        await ctx.progress(S, 5, f"Root asset {ioc.type}: {ioc.value}")

        host_asset: Doc | None = ctx.state.get("host_asset")
        # DNS/WHOIS first (fast) so content validation can use resolution + registry status.
        if host_asset is not None and host_asset["type"] == AssetType.DOMAIN:
            await self._domain_infra(ctx, host_asset)
        ctx.check_cancelled()
        if ioc.url:
            profile = await WebProfiler(ctx, S).profile(
                ioc.url,
                host_asset or root,
                screenshots=ctx.options.screenshots,
                retry_http=ioc.type == IOCType.DOMAIN,
            )
            ctx.state["page"] = profile.page
            ctx.state["web_profile"] = profile
        ctx.check_cancelled()

        await ctx.progress(S, 85, "Mapping IP addresses to ASN / hosting")
        await self._ip_infra(ctx)
        await self._update_host_profile(ctx)
        page = ctx.state.get("page")
        web_profile = ctx.state.get("web_profile")
        status = f"HTTP {page.status_code}" if page and page.status_code else (page.error if page else "no web content")
        verdict = f", {web_profile.content.get('status')}" if web_profile and web_profile.content else ""
        return f"Collected {ioc.value} ({status}{verdict}); {len(ctx.state.get('ips', set()))} IP(s)"

    # ------------------------------------------------------------------ root
    async def _create_root(self, ctx: InvestigationContext, ioc: ParsedIOC) -> Doc:
        if ioc.type == IOCType.URL:
            url_asset = await ctx.add_asset(AssetType.URL, ioc.value, source="input", extra={"is_root": True})
            assert url_asset is not None
            host = ioc.host or ""
            host_asset = await ctx.add_asset(host_asset_type(host), host, source="input")
            if host_asset:
                await ctx.link(host_asset, url_asset, RelationType.HAS_URL, provider="input")
                ctx.state["host_asset"] = host_asset
                if host_asset["type"] == AssetType.IP:
                    ctx.state.setdefault("ips", set()).add(host)
            return url_asset
        asset_type = {
            IOCType.DOMAIN: AssetType.DOMAIN,
            IOCType.IP: AssetType.IP,
            IOCType.CERTIFICATE: AssetType.CERTIFICATE,
        }[ioc.type]
        root = await ctx.add_asset(asset_type, ioc.value, source="input", extra={"is_root": True})
        assert root is not None
        if ioc.type in (IOCType.DOMAIN, IOCType.IP):
            ctx.state["host_asset"] = root
        if ioc.type == IOCType.IP:
            ctx.state.setdefault("ips", set()).add(ioc.value)
        return root

    # ------------------------------------------------------------------ infrastructure
    async def _domain_infra(self, ctx: InvestigationContext, domain_asset: Doc) -> None:
        await ctx.progress(S, 8, "Resolving DNS, RDAP and WHOIS")
        ioc = parse_ioc(domain_asset["value"])
        names = await ctx.providers.eligible(IOCType.DOMAIN, names=CORE_DOMAIN_PROVIDERS)
        runs = await ctx.providers.run_many(names, ioc)
        for run in runs:
            await ctx.record_provider_run(run, domain_asset, S)
            if run.ok:
                n = await ctx.apply_related(domain_asset, run.result.related, run.provider)
                await ctx.log(S, f"{run.provider}: ok{' (cached)' if run.cached else ''}, {n} related")
                if run.provider == "dns":
                    for ip in run.result.summary.get("a", []) + run.result.summary.get("aaaa", []):
                        ctx.state.setdefault("ips", set()).add(ip)
                    ctx.state["dns"] = run.result.summary
                elif run.provider in ("rdap", "whois"):
                    ctx.state[run.provider] = run.result.summary
            elif not run.skipped:
                await ctx.log(S, f"{run.provider}: {run.error}", "warning")

    async def _ip_infra(self, ctx: InvestigationContext) -> None:
        ips = [ip for ip in sorted(ctx.state.get("ips", set())) if is_public_ip(ip)][:MAX_IPS]
        profiles: dict[str, dict[str, Any]] = {}

        async def one(index: int, ip: str) -> None:
            ip_asset = await ctx.add_asset(AssetType.IP, ip, source="dns")
            if ip_asset is None:
                return
            wanted = CORE_IP_PROVIDERS if index < 3 else ["cymru"]
            names = await ctx.providers.eligible(IOCType.IP, names=wanted)
            runs = await ctx.providers.run_many(names, parse_ioc(ip))
            profile: dict[str, Any] = {}
            for run in runs:
                await ctx.record_provider_run(run, ip_asset, S)
                if not run.ok:
                    continue
                await ctx.apply_related(ip_asset, run.result.related, run.provider)
                s = run.result.summary
                if run.provider == "cymru":
                    profile.update({k: s.get(k) for k in ("asn", "as_name", "prefix", "country", "hosting_provider")})
                elif run.provider == "rdap":
                    profile.setdefault("network_name", s.get("network_name"))
                    profile.setdefault("country", s.get("country"))
                elif run.provider == "dns":
                    profile["ptr"] = s.get("ptr", [])
            profiles[ip] = profile
            update: dict[str, Any] = {"attributes.network": profile}
            if profile.get("asn"):
                update.update(
                    {"fingerprints.asn": profile["asn"], "fingerprints.hosting": profile.get("hosting_provider")}
                )
            await ctx.assets.raw_update(ip_asset["_id"], {"$set": update})

        await asyncio.gather(*(one(i, ip) for i, ip in enumerate(ips)))
        ctx.check_cancelled()
        await ctx.progress(S, 95, f"Mapped {len(profiles)} IP address(es)")
        ctx.state["ip_profiles"] = profiles

    async def _update_host_profile(self, ctx: InvestigationContext) -> None:
        host_asset = ctx.state.get("host_asset")
        if host_asset is None:
            return
        dns = ctx.state.get("dns") or {}
        rdap = ctx.state.get("rdap") or {}
        whois = ctx.state.get("whois") or {}
        profiles: dict[str, dict[str, Any]] = ctx.state.get("ip_profiles") or {}
        first = next(iter(profiles.values()), {})
        infra = {
            "ips": sorted(ctx.state.get("ips", set())),
            "nameservers": dns.get("ns") or rdap.get("nameservers") or whois.get("nameservers") or [],
            "mx": dns.get("mx", []),
            "registrar": rdap.get("registrar") or whois.get("registrar"),
            "created": rdap.get("created") or whois.get("created"),
            "expires": rdap.get("expires") or whois.get("expires"),
            "registrant_org": rdap.get("registrant_org") or whois.get("registrant_org"),
            "abuse_email": rdap.get("abuse_email") or whois.get("abuse_email"),
            "registry_status": rdap.get("status") or whois.get("status") or [],
            "asns": sorted({p["asn"] for p in profiles.values() if p.get("asn")}),
            "hosting_providers": sorted(
                {p["hosting_provider"] for p in profiles.values() if p.get("hosting_provider")}
            ),
            "country": first.get("country"),
        }
        fingerprints = {
            "nameservers": infra["nameservers"],
            "asns": infra["asns"],
            "hosting": infra["hosting_providers"],
            "ips": infra["ips"],
            "registrar": infra["registrar"],
        }
        ctx.state["infra"] = infra
        await ctx.assets.raw_update(
            host_asset["_id"],
            {
                "$set": {
                    "attributes.infrastructure": infra,
                    **{f"fingerprints.{k}": v for k, v in fingerprints.items() if v},
                }
            },
        )
        if ctx.root_asset and ctx.root_asset["_id"] != host_asset["_id"]:
            await ctx.assets.raw_update(ctx.root_asset["_id"], {"$set": {"attributes.infrastructure": infra}})
