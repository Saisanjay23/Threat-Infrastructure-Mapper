"""Screenshot engine (Playwright + stealth).

Playwright needs an event loop that supports subprocesses (Proactor on Windows). Uvicorn may run a
Selector loop, so the browser lives on a dedicated thread with its own Proactor loop; callers
submit coroutines with `BrowserEngine.capture()` from any loop.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import logging
import sys
import threading
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from PIL import Image

from app.core.config import get_settings

log = logging.getLogger(__name__)

DESKTOP_VIEWPORT = {"width": 1920, "height": 1080}
THUMBNAIL_SIZE = (480, 270)
FULLPAGE_MAX_HEIGHT = 12000


@dataclass
class CaptureResult:
    url: str
    final_url: str | None = None
    title: str | None = None
    status: int | None = None
    desktop_png: bytes | None = None
    mobile_png: bytes | None = None
    fullpage_png: bytes | None = None
    thumbnail_jpg: bytes | None = None
    rendered_html: str | None = None
    console_errors: list[str] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def meta(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "status": self.status,
            "has_desktop": self.desktop_png is not None,
            "has_mobile": self.mobile_png is not None,
            "has_fullpage": self.fullpage_png is not None,
            "console_errors": self.console_errors[:50],
            "request_count": len(self.requests),
            "error": self.error,
        }


def make_thumbnail(png: bytes, size: tuple[int, int] = THUMBNAIL_SIZE) -> bytes:
    with Image.open(io.BytesIO(png)) as src:
        img = src.convert("RGB")
        img.thumbnail(size, Image.Resampling.LANCZOS)
        out = io.BytesIO()
        img.save(out, format="JPEG", quality=80, optimize=True)
        return out.getvalue()


def _clip_fullpage(png: bytes) -> bytes:
    with Image.open(io.BytesIO(png)) as img:
        if img.height <= FULLPAGE_MAX_HEIGHT:
            return png
        cropped = img.crop((0, 0, img.width, FULLPAGE_MAX_HEIGHT))
        out = io.BytesIO()
        cropped.save(out, format="PNG", optimize=True)
        return out.getvalue()


def is_internal_host(host: str | None) -> bool:
    """Literal private/loopback IPs and local hostnames are never fetched by the browser."""
    if not host:
        return False
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


async def _guard_route(route: Any) -> None:
    host = urlsplit(route.request.url).hostname
    if route.request.url.startswith(("http://", "https://")) and is_internal_host(host):
        await route.abort("blockedbyclient")
    else:
        await route.continue_()


class BrowserEngine:
    _instance: BrowserEngine | None = None

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._playwright: Any = None
        self._browser: Any = None
        self._lock: asyncio.Lock | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self.available: bool | None = None
        self.last_error: str | None = None

    @classmethod
    def instance(cls) -> BrowserEngine:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------ thread/loop plumbing
    def _ensure_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def runner() -> None:
            loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()  # type: ignore[attr-defined]
            asyncio.set_event_loop(loop)
            self._loop = loop
            self._lock = asyncio.Lock()
            self._semaphore = asyncio.Semaphore(3)
            self._ready.set()
            loop.run_forever()

        self._ready.clear()
        self._thread = threading.Thread(target=runner, name="tim-browser", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10)

    def _submit(self, coro: Any) -> Future:
        self._ensure_thread()
        assert self._loop is not None
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    async def _ensure_browser(self) -> Any:
        assert self._lock is not None
        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            from playwright.async_api import async_playwright

            if self._playwright is None:
                self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-default-browser-check",
                    "--disable-dev-shm-usage",
                ],
            )
            return self._browser

    # ------------------------------------------------------------------ capture
    async def _capture(self, url: str, mobile: bool, fullpage: bool) -> CaptureResult:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import TimeoutError as PlaywrightTimeout
        from playwright_stealth import Stealth

        settings = get_settings()
        result = CaptureResult(url=url)
        assert self._semaphore is not None
        async with self._semaphore:
            try:
                browser = await self._ensure_browser()
            except Exception as exc:
                self.available = False
                self.last_error = f"{type(exc).__name__}: {exc}"
                result.error = f"browser unavailable: {self.last_error}"
                return result
            self.available = True
            stealth = Stealth()
            context = await browser.new_context(
                viewport=DESKTOP_VIEWPORT,
                user_agent=settings.user_agent,
                ignore_https_errors=True,
                java_script_enabled=True,
                locale="en-US",
            )
            try:
                await stealth.apply_stealth_async(context)
                if not settings.allow_private_targets:
                    await context.route("**/*", _guard_route)
                page = await context.new_page()
                page.on("console", lambda m: result.console_errors.append(m.text[:300]) if m.type == "error" else None)
                page.on(
                    "request",
                    lambda r: (
                        result.requests.append({"url": r.url[:500], "type": r.resource_type})
                        if len(result.requests) < 500
                        else None
                    ),
                )
                try:
                    response = await page.goto(
                        url, wait_until="domcontentloaded", timeout=settings.screenshot_timeout_ms
                    )
                    result.status = response.status if response else None
                    try:
                        await page.wait_for_load_state("networkidle", timeout=8000)
                    except PlaywrightTimeout:
                        pass
                except PlaywrightTimeout:
                    result.error = "navigation timeout (partial render captured)"
                result.final_url = page.url
                result.title = await page.title()
                result.rendered_html = (await page.content())[: settings.max_html_bytes]
                result.desktop_png = await page.screenshot(type="png", timeout=15000)
                if fullpage:
                    try:
                        result.fullpage_png = _clip_fullpage(
                            await page.screenshot(type="png", full_page=True, timeout=20000)
                        )
                    except PlaywrightError as exc:
                        log.debug("full page screenshot failed: %s", exc)
                result.thumbnail_jpg = make_thumbnail(result.desktop_png)
            except PlaywrightError as exc:
                result.error = f"capture failed: {exc.message if hasattr(exc, 'message') else exc}"[:500]
            finally:
                await context.close()

            if mobile and result.desktop_png is not None:
                device = self._playwright.devices.get("iPhone 13") or {}
                mctx = await browser.new_context(**device, ignore_https_errors=True, locale="en-US")
                try:
                    await stealth.apply_stealth_async(mctx)
                    mpage = await mctx.new_page()
                    try:
                        await mpage.goto(url, wait_until="domcontentloaded", timeout=settings.screenshot_timeout_ms)
                        try:
                            await mpage.wait_for_load_state("networkidle", timeout=6000)
                        except PlaywrightTimeout:
                            pass
                    except PlaywrightTimeout:
                        pass
                    result.mobile_png = await mpage.screenshot(type="png", timeout=15000)
                except PlaywrightError as exc:
                    log.debug("mobile screenshot failed: %s", exc)
                finally:
                    await mctx.close()
        return result

    async def capture(
        self, url: str, *, mobile: bool = True, fullpage: bool = True, timeout: float = 120.0
    ) -> CaptureResult:
        future = self._submit(self._capture(url, mobile, fullpage))
        try:
            return await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)
        except TimeoutError:
            future.cancel()
            return CaptureResult(url=url, error="screenshot engine timeout")

    async def _close(self) -> None:
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright is not None:
            await self._playwright.stop()
        self._browser = self._playwright = None

    async def shutdown(self) -> None:
        if self._loop is None or not self._thread or not self._thread.is_alive():
            return
        try:
            await asyncio.wait_for(asyncio.wrap_future(self._submit(self._close())), timeout=15)
        except (TimeoutError, RuntimeError):
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._thread = None
        self._loop = None
