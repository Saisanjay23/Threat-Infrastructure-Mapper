"""Reusable web profiling of a single host/URL.

Used by the collection stage for the root IOC and by the pivot stage for discovered candidates:
HTTP + redirect chain, TLS, favicon, screenshots, website fingerprints (trackers, forms, logos,
structure hashes), Content Validation and Brand Impersonation.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from app.analysis.brand import assess_brand
from app.analysis.content import classify_content
from app.collectors import favicon as favicon_collector
from app.collectors import tls as tls_collector
from app.collectors import web as web_collector
from app.collectors.browser import BrowserEngine, CaptureResult
from app.collectors.web import PageFetch
from app.core.config import get_settings
from app.fingerprints.images import image_fingerprints, perceptual_hashes
from app.fingerprints.website import extract_website_fingerprints
from app.models.common import AssetType, IOCType
from app.models.graph import RelationType
from app.pipeline.context import InvestigationContext
from app.repositories.base import Doc
from app.utils.ioc import is_ip

log = logging.getLogger(__name__)

TRACKER_RELATION = {
    "analytics": RelationType.SHARES_ANALYTICS,
    "pixel": RelationType.SHARES_PIXEL,
    "tracking": RelationType.SHARES_TRACKING,
}
MAX_LOGOS = 2


def host_asset_type(host: str) -> AssetType:
    return AssetType.IP if is_ip(host) else AssetType.DOMAIN


@dataclass
class WebProfile:
    page: PageFetch
    final_host_asset: Doc
    capture: CaptureResult | None = None
    tls: dict[str, Any] | None = None
    favicon: dict[str, Any] | None = None
    fingerprints: dict[str, Any] = field(default_factory=dict)
    content: dict[str, Any] = field(default_factory=dict)
    brand: dict[str, Any] = field(default_factory=dict)
    web: dict[str, Any] = field(default_factory=dict)


class WebProfiler:
    """Collects and analyses one URL. `stage` controls where progress and events are reported."""

    def __init__(self, ctx: InvestigationContext, stage: str, *, report_progress: bool = True) -> None:
        self.ctx = ctx
        self.stage = stage
        self.report = report_progress

    async def _progress(self, pct: int, message: str) -> None:
        if self.report:
            await self.ctx.progress(self.stage, pct, message)

    async def _log(self, message: str, level: str = "info") -> None:
        if self.report:
            await self.ctx.log(self.stage, message, level)

    # ------------------------------------------------------------------ entry point
    async def profile(
        self,
        url: str,
        host_asset: Doc,
        *,
        screenshots: bool,
        retry_http: bool = False,
        source: str = "http",
    ) -> WebProfile:
        ctx = self.ctx
        settings = get_settings()
        await self._progress(10, f"Fetching {url}")
        page = await web_collector.fetch_page(url)
        if not page.ok and retry_http and url.startswith("https://"):
            await self._log(f"HTTPS fetch failed ({page.error}); retrying over HTTP", "warning")
            fallback = await web_collector.fetch_page("http://" + url.removeprefix("https://"))
            if fallback.ok:
                page = fallback
        ctx.check_cancelled()
        if page.ok:
            await self._log(f"HTTP {page.status_code} from {page.final_url} via {len(page.redirect_chain)} hop(s)")
        else:
            await self._log(f"Web collection failed: {page.error}", "warning")
        await ctx.artifacts.store_json(
            "http_response", page.to_dict(), investigation_id=ctx.id, asset_id=host_asset["_id"]
        )
        if page.html:
            await ctx.artifacts.store_file(
                "html",
                page.body,
                filename="page.html",
                content_type=page.content_type or "text/html",
                investigation_id=ctx.id,
                asset_id=host_asset["_id"],
                metadata={"url": page.final_url},
            )
        await self._redirects(page, host_asset, source)
        await self._progress(35, "HTTP collection complete")

        final_url = page.final_url or url
        final_host = urlsplit(final_url).hostname or urlsplit(url).hostname or ""
        final_host_asset = await ctx.add_asset(host_asset_type(final_host), final_host, source=source) or host_asset
        result = WebProfile(page=page, final_host_asset=final_host_asset)
        if page.ip:
            ctx.state.setdefault("ips", set()).add(page.ip)
            ip_asset = await ctx.add_asset(AssetType.IP, page.ip, source=source)
            if ip_asset and final_host_asset["type"] == AssetType.DOMAIN:
                await ctx.link(
                    final_host_asset,
                    ip_asset,
                    RelationType.RESOLVES_TO,
                    provider=source,
                    evidence={"observed": "http connection"},
                )

        jobs: list[Any] = []
        if final_url.startswith("https://") or ctx.ioc.type in (IOCType.DOMAIN, IOCType.IP):
            jobs.append(self._tls(result, final_host, urlsplit(final_url).port or 443, final_host_asset, source))
        if page.ok:
            jobs.append(self._favicon(result, page, final_host_asset, source))
        if screenshots and settings.screenshots_enabled:
            jobs.append(self._screenshots(result, final_url if page.ok else url, final_host_asset))
        await asyncio.gather(*jobs)

        await self._analyze(result, host_asset, source)

        targets = {final_host_asset["_id"], host_asset["_id"]}
        if (
            ctx.root_asset is not None
            and ctx.root_asset.get("type") == AssetType.URL
            and ctx.root_asset["_id"] not in targets
            and url == ctx.ioc.url
        ):
            targets.add(ctx.root_asset["_id"])
        update = {
            "attributes.web": result.web,
            "attributes.website": _website_summary(result.fingerprints),
            "attributes.content": result.content,
            "attributes.brand": result.brand,
            "status": result.content.get("status", "UNKNOWN"),
            "impersonation_score": result.brand.get("impersonation_score"),
            "brand_similarity_score": result.brand.get("brand_similarity_score"),
        }
        # Display attributes collected on the final (post-redirect) host are mirrored onto the requested
        # host/URL so the root profile is complete; fingerprints stay on the host that actually served them.
        final_doc = await ctx.assets.get(final_host_asset["_id"], {"attributes": 1}) or {}
        for key in ("tls", "favicon", "screenshots", "title"):
            value = (final_doc.get("attributes") or {}).get(key)
            if value is not None:
                update[f"attributes.{key}"] = value
        for aid in targets:
            await ctx.assets.raw_update(aid, {"$set": update})
        return result

    # ------------------------------------------------------------------ pieces
    async def _redirects(self, page: PageFetch, host_asset: Doc, source: str) -> None:
        ctx = self.ctx
        previous: Doc | None = None
        for index, hop in enumerate(page.redirect_chain):
            host = urlsplit(hop.url).hostname
            if not host:
                continue
            url_asset = await ctx.add_asset(
                AssetType.URL, hop.url, source=source, attributes={"status_code": hop.status, "server": hop.server}
            )
            hop_host = await ctx.add_asset(host_asset_type(host), host, source=source)
            if url_asset and hop_host:
                await ctx.link(hop_host, url_asset, RelationType.HAS_URL, provider=source)
            if previous is not None and url_asset is not None:
                prev_hop = page.redirect_chain[index - 1]
                await ctx.link(
                    previous,
                    url_asset,
                    RelationType.REDIRECTS_TO,
                    provider=source,
                    evidence={"hop": index, "status": prev_hop.status, "kind": prev_hop.kind},
                )
            previous = url_asset
        if len(page.redirect_chain) > 1:
            await ctx.artifacts.store_json(
                "redirect_chain",
                [h.__dict__ for h in page.redirect_chain],
                investigation_id=ctx.id,
                asset_id=host_asset["_id"],
            )
        if page.headers:
            await ctx.artifacts.store_json("headers", page.headers, investigation_id=ctx.id, asset_id=host_asset["_id"])
        if page.cookies:
            await ctx.artifacts.store_json("cookies", page.cookies, investigation_id=ctx.id, asset_id=host_asset["_id"])

    async def _tls(self, result: WebProfile, host: str, port: int, host_asset: Doc, source: str) -> None:
        ctx = self.ctx
        await self._progress(40, f"Collecting TLS certificate from {host}:{port}")
        tls = await tls_collector.collect_tls(host, port)
        await ctx.artifacts.store_json("tls", tls, investigation_id=ctx.id, asset_id=host_asset["_id"])
        cert = tls.get("certificate")
        if not cert:
            await self._log(f"No TLS certificate: {tls.get('error')}", "warning")
            return
        result.tls = tls
        attrs = {
            k: cert.get(k)
            for k in (
                "sha1",
                "md5",
                "spki_sha256",
                "serial",
                "subject",
                "subject_cn",
                "subject_org",
                "issuer",
                "issuer_cn",
                "issuer_org",
                "san",
                "not_before",
                "not_after",
                "validity_days",
                "self_signed",
                "wildcard",
                "key_type",
                "key_size",
                "signature_algorithm",
            )
        }
        attrs["trusted"] = tls.get("trusted")
        attrs["validation_error"] = tls.get("validation_error")
        cert_asset = await ctx.add_asset(
            AssetType.CERTIFICATE,
            cert["sha256"],
            source="tls",
            attributes=attrs,
            fingerprints={"cert_sha256": cert["sha256"], "cert_sha1": cert["sha1"], "spki_sha256": cert["spki_sha256"]},
        )
        if cert_asset is None:
            return
        await ctx.link(
            host_asset,
            cert_asset,
            RelationType.USES_CERTIFICATE,
            provider="tls",
            evidence={"port": port, "protocol": tls.get("protocol")},
        )
        await ctx.assets.raw_update(
            host_asset["_id"],
            {
                "$set": {
                    "fingerprints.cert_sha256": cert["sha256"],
                    "fingerprints.cert_sha1": cert["sha1"],
                    "fingerprints.cert_issuer": cert.get("issuer_org") or cert.get("issuer_cn"),
                    "attributes.tls": {
                        "protocol": tls.get("protocol"),
                        "cipher": tls.get("cipher"),
                        "trusted": tls.get("trusted"),
                        "issuer_org": cert.get("issuer_org"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                        "sha256": cert["sha256"],
                        "san_count": len(cert.get("san", [])),
                    },
                }
            },
        )
        host = host_asset["value"]
        for san in cert.get("san", [])[:50]:
            name = san.lstrip("*.")
            if name == host or not name or is_ip(name):
                continue
            san_asset = await ctx.add_asset(AssetType.DOMAIN, name, source="tls")
            if san_asset:
                await ctx.link(
                    san_asset,
                    cert_asset,
                    RelationType.USES_CERTIFICATE,
                    provider="tls",
                    evidence={"via": "subjectAltName"},
                )
        await self._log(
            f"Certificate {cert['sha256'][:16]}... issued by "
            f"{cert.get('issuer_org') or cert.get('issuer_cn')} ({len(cert.get('san', []))} SAN)"
        )

    async def _favicon(self, result: WebProfile, page: PageFetch, host_asset: Doc, source: str) -> None:
        ctx = self.ctx
        await self._progress(45, "Downloading favicon")
        icon = await favicon_collector.fetch_favicon(page.html, page.final_url or page.requested_url)
        if icon is None:
            await self._log("No favicon found")
            return
        fp = image_fingerprints(icon.content)
        artifact = await ctx.artifacts.store_file(
            "favicon",
            icon.content,
            filename="favicon",
            content_type=icon.content_type or "image/x-icon",
            investigation_id=ctx.id,
            asset_id=host_asset["_id"],
            metadata={"url": icon.url},
        )
        result.favicon = {"url": icon.url, "file_id": artifact["file_id"], **fp}
        fav_asset = await ctx.add_asset(
            AssetType.FAVICON,
            fp["mmh3"],
            source=source,
            attributes={
                "url": icon.url,
                "md5": fp["md5"],
                "sha256": fp["sha256"],
                "size": fp["size"],
                "width": icon.width,
                "height": icon.height,
                "format": icon.format,
                "file_id": artifact["file_id"],
                "phash": fp.get("phash"),
            },
            fingerprints={
                "favicon_mmh3": fp["mmh3"],
                "favicon_md5": fp["md5"],
                "favicon_sha256": fp["sha256"],
                "favicon_phash": fp.get("phash"),
            },
        )
        if fav_asset:
            await ctx.link(
                host_asset, fav_asset, RelationType.SHARES_FAVICON, provider=source, evidence={"url": icon.url}
            )
        await ctx.assets.raw_update(
            host_asset["_id"],
            {
                "$set": {
                    "fingerprints.favicon_mmh3": fp["mmh3"],
                    "fingerprints.favicon_md5": fp["md5"],
                    "fingerprints.favicon_sha256": fp["sha256"],
                    "fingerprints.favicon_phash": fp.get("phash"),
                    "attributes.favicon": {"url": icon.url, "file_id": artifact["file_id"], "mmh3": fp["mmh3"]},
                }
            },
        )
        await self._log(f"Favicon mmh3={fp['mmh3']} md5={fp['md5']}")

    async def _screenshots(self, result: WebProfile, url: str, host_asset: Doc) -> None:
        ctx = self.ctx
        await self._progress(50, "Rendering page in headless browser")
        capture = await BrowserEngine.instance().capture(url, mobile=self.report, fullpage=self.report)
        result.capture = capture
        if capture.error:
            await self._log(f"Screenshot: {capture.error}", "warning")
        files: dict[str, str] = {}
        for kind, content, ctype, fname in (
            ("screenshot_desktop", capture.desktop_png, "image/png", "desktop.png"),
            ("screenshot_mobile", capture.mobile_png, "image/png", "mobile.png"),
            ("screenshot_fullpage", capture.fullpage_png, "image/png", "fullpage.png"),
            ("screenshot_thumbnail", capture.thumbnail_jpg, "image/jpeg", "thumbnail.jpg"),
        ):
            if content:
                art = await ctx.artifacts.store_file(
                    kind,
                    content,
                    filename=fname,
                    content_type=ctype,
                    investigation_id=ctx.id,
                    asset_id=host_asset["_id"],
                    metadata={"url": url, "final_url": capture.final_url},
                )
                files[kind.removeprefix("screenshot_")] = art["file_id"]
        if capture.rendered_html:
            await ctx.artifacts.store_file(
                "rendered_html",
                capture.rendered_html.encode("utf-8"),
                filename="rendered.html",
                content_type="text/html; charset=utf-8",
                investigation_id=ctx.id,
                asset_id=host_asset["_id"],
                metadata={"final_url": capture.final_url},
            )
        await ctx.artifacts.store_json(
            "browser_capture", capture.meta(), investigation_id=ctx.id, asset_id=host_asset["_id"]
        )
        if files:
            shot_fp = perceptual_hashes(capture.desktop_png) if capture.desktop_png else {}
            await ctx.assets.raw_update(
                host_asset["_id"],
                {
                    "$set": {
                        "attributes.screenshots": files,
                        "attributes.rendered_final_url": capture.final_url,
                        **(
                            {
                                "fingerprints.screenshot_phash": shot_fp["phash"],
                                "fingerprints.screenshot_dhash": shot_fp["dhash"],
                            }
                            if shot_fp
                            else {}
                        ),
                    }
                },
            )
            if ctx.root_asset and ctx.root_asset["_id"] != host_asset["_id"] and self.report:
                await ctx.assets.raw_update(ctx.root_asset["_id"], {"$set": {"attributes.screenshots": files}})
            await self._log(f"Captured {len(files)} screenshot(s)")
        await self._progress(70, "Screenshots complete")

    async def _logos(self, fp: dict[str, Any], host_asset: Doc, source: str) -> list[str]:
        ctx = self.ctx
        hashes: list[str] = []
        for cand in fp.get("logo_candidates", [])[:MAX_LOGOS]:
            src = cand["src"]
            content: bytes | None = None
            if src.startswith("data:image") and ";base64," in src:
                try:
                    content = base64.b64decode(src.split(";base64,", 1)[1], validate=False)
                except ValueError:
                    content = None
            elif src.startswith(("http://", "https://")):
                fetched = await web_collector.fetch_binary(src, 2 * 1024 * 1024)
                if fetched and fetched[0] == 200:
                    content = fetched[1]
            if not content:
                continue
            ifp = image_fingerprints(content)
            if not ifp.get("phash"):
                continue
            _, _, fmt = favicon_collector.inspect_image(content)
            art = await ctx.artifacts.store_file(
                "logo",
                content,
                filename="logo",
                content_type=f"image/{(fmt or 'png').lower()}",
                investigation_id=ctx.id,
                asset_id=host_asset["_id"],
                metadata={"url": src[:500], "alt": cand.get("alt")},
            )
            logo_asset = await ctx.add_asset(
                AssetType.LOGO,
                ifp["sha256"],
                source=source,
                attributes={
                    "url": src[:500] if not src.startswith("data:") else "inline data URI",
                    "alt": cand.get("alt"),
                    "file_id": art["file_id"],
                    "phash": ifp["phash"],
                    "ahash": ifp.get("ahash"),
                    "dhash": ifp.get("dhash"),
                },
                fingerprints={
                    "logo_phash": ifp["phash"],
                    "logo_ahash": ifp.get("ahash"),
                    "logo_dhash": ifp.get("dhash"),
                },
            )
            if logo_asset:
                await ctx.link(
                    host_asset, logo_asset, RelationType.SHARES_LOGO, provider=source, evidence={"alt": cand.get("alt")}
                )
            hashes.append(ifp["phash"])
        return hashes

    async def _brand_reference_hashes(self, brand: str | None) -> list[str]:
        query: dict[str, Any] = {"type": "logo", "attributes.reference": True}
        if brand:
            query["attributes.brand_lc"] = brand.strip().lower()
        docs = await self.ctx.db["assets"].find(query, {"fingerprints.logo_phash": 1}).to_list(length=50)
        return [d["fingerprints"]["logo_phash"] for d in docs if d.get("fingerprints", {}).get("logo_phash")]

    async def _analyze(self, result: WebProfile, host_asset: Doc, source: str) -> None:
        ctx = self.ctx
        page = result.page
        capture = result.capture
        final_url = page.final_url or page.requested_url
        html = page.html or (capture.rendered_html if capture else "") or ""
        target = result.final_host_asset
        fp: dict[str, Any] = {}
        if html:
            fp = extract_website_fingerprints(html, final_url, extra_html=capture.rendered_html if capture else None)
            result.fingerprints = fp
            await ctx.artifacts.store_json("fingerprints", fp, investigation_id=ctx.id, asset_id=target["_id"])
            await self._trackers(fp, target, source)
            logo_hashes = await self._logos(fp, target, source)
            await ctx.assets.raw_update(
                target["_id"],
                {
                    "$set": {
                        "fingerprints.title_hash": fp.get("title_hash"),
                        "fingerprints.title_normalized": fp.get("title_normalized"),
                        "fingerprints.html_simhash": fp.get("dom_simhash"),
                        "fingerprints.text_simhash": fp.get("text_simhash"),
                        "fingerprints.html_sha256": fp.get("html_sha256"),
                        "fingerprints.logo_phashes": logo_hashes,
                        "attributes.title": fp.get("title"),
                    }
                },
            )
        else:
            logo_hashes = []

        is_primary = host_asset["_id"] == (ctx.state.get("host_asset") or {}).get("_id")
        dns = ctx.state.get("dns") if is_primary else None
        rdap = ctx.state.get("rdap") or {}
        whois = ctx.state.get("whois") or {}
        registry_status = (rdap.get("status") or []) + (whois.get("status") or []) if dns is not None else []
        verdict = classify_content(
            status_code=page.status_code,
            html=html,
            text=fp.get("text_excerpt"),
            title=fp.get("title"),
            fetch_error=page.error if not page.ok else None,
            dns_resolves=(dns or {}).get("resolves") if dns is not None else None,
            nameservers=(dns or {}).get("ns"),
            registry_status=registry_status,
            word_count=fp.get("word_count"),
            has_login_form=bool(fp.get("has_login_form")),
        )
        result.content = verdict.to_dict()
        page_hashes = list(logo_hashes)
        if result.favicon and result.favicon.get("phash"):
            page_hashes.append(result.favicon["phash"])
        brand = assess_brand(
            target["value"],
            fp,
            brand=ctx.options.brand,
            brand_domains=ctx.options.brand_domains,
            brand_logo_hashes=await self._brand_reference_hashes(ctx.options.brand),
            page_logo_hashes=page_hashes,
            site_active=verdict.status.value == "ACTIVE",
        )
        result.brand = brand.to_dict()
        result.web = {
            "final_url": page.final_url,
            "status_code": page.status_code,
            "title": (capture.title if capture and capture.title else None) or fp.get("title"),
            "server": page.headers.get("server"),
            "content_type": page.content_type,
            "content_length": len(page.body),
            "redirect_count": max(len(page.redirect_chain) - 1, 0),
            "http_version": page.http_version,
            "ip": page.ip,
            "fetch_error": page.error,
            "elapsed_ms": page.elapsed_ms,
        }
        await self._log(f"Content: {verdict.status.value} ({verdict.confidence}%) - {'; '.join(verdict.reasons[:3])}")
        if brand.brand:
            await self._log(
                f"Brand '{brand.brand}'{' (inferred)' if brand.brand_inferred else ''}: similarity "
                f"{brand.brand_similarity_score}, impersonation {brand.impersonation_score}"
            )
        elif brand.impersonation_score:
            await self._log(f"Credential-harvesting indicators: impersonation {brand.impersonation_score}")

    async def _trackers(self, fp: dict[str, Any], host_asset: Doc, source: str) -> None:
        ctx = self.ctx
        analytics: list[str] = []
        gtm: list[str] = []
        pixels: list[str] = []
        for asset_type, items in (fp.get("trackers") or {}).items():
            for item in items:
                tracker = await ctx.add_asset(
                    asset_type,
                    item["id"],
                    source=source,
                    attributes={"family": item["family"]},
                    fingerprints={"tracking_id": item["id"]},
                )
                if tracker is None:
                    continue
                await ctx.link(
                    host_asset,
                    tracker,
                    TRACKER_RELATION[asset_type],
                    provider=source,
                    evidence={"family": item["family"]},
                )
                if item["family"] == "gtm":
                    gtm.append(item["id"])
                elif asset_type == "analytics":
                    analytics.append(item["id"])
                elif asset_type == "pixel":
                    pixels.append(item["id"])
        await ctx.assets.raw_update(
            host_asset["_id"],
            {
                "$set": {
                    "fingerprints.tracking_ids": fp.get("tracking_ids", []),
                    "fingerprints.analytics_ids": sorted(analytics),
                    "fingerprints.gtm_ids": sorted(gtm),
                    "fingerprints.pixel_ids": sorted(pixels),
                }
            },
        )
        if fp.get("tracking_ids"):
            await self._log(f"Tracking IDs: {', '.join(fp['tracking_ids'][:8])}")


def _website_summary(fp: dict[str, Any]) -> dict[str, Any]:
    if not fp:
        return {}
    return {
        "title": fp.get("title"),
        "language": fp.get("language"),
        "meta": fp.get("meta"),
        "form_count": fp.get("form_count"),
        "password_fields": fp.get("password_fields"),
        "has_login_form": fp.get("has_login_form"),
        "external_form_actions": fp.get("external_form_actions"),
        "forms": fp.get("forms", [])[:5],
        "tracking_ids": fp.get("tracking_ids"),
        "trackers": fp.get("trackers"),
        "script_hosts": (fp.get("scripts") or {}).get("hosts", [])[:30],
        "external_hosts": fp.get("external_hosts", [])[:30],
        "technologies": fp.get("technologies"),
        "emails": fp.get("emails"),
        "telegram_exfil": fp.get("telegram_exfil"),
        "crypto_wallets": fp.get("crypto_wallets"),
        "word_count": fp.get("word_count"),
        "logo_candidates": fp.get("logo_candidates"),
    }
