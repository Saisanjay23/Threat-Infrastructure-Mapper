"""Favicon discovery and download."""

from __future__ import annotations

import io
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from PIL import Image, UnidentifiedImageError

from app.collectors.web import fetch_binary

MAX_FAVICON_BYTES = 1024 * 1024


@dataclass
class Favicon:
    url: str
    content: bytes
    content_type: str | None
    width: int | None = None
    height: int | None = None
    format: str | None = None


def discover_favicon_urls(html: str, page_url: str) -> list[str]:
    candidates: list[str] = []
    if html:
        soup = BeautifulSoup(html[:500_000], "lxml")
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            if "icon" in rel:
                href = str(link["href"]).strip()
                if href.startswith("data:"):
                    continue
                candidates.append(urljoin(page_url, href))
    parts = urlsplit(page_url)
    candidates.append(f"{parts.scheme}://{parts.netloc}/favicon.ico")
    unique: list[str] = []
    for c in candidates:
        if c.startswith(("http://", "https://")) and c not in unique:
            unique.append(c)
    return unique


def inspect_image(content: bytes) -> tuple[int | None, int | None, str | None]:
    try:
        with Image.open(io.BytesIO(content)) as img:
            return img.width, img.height, img.format
    except (UnidentifiedImageError, OSError, ValueError):
        return None, None, None


def _is_svg(content: bytes, content_type: str | None) -> bool:
    return (content_type or "").startswith("image/svg") or content[:512].lstrip().lower().startswith(
        (b"<svg", b"<?xml")
    )


async def fetch_favicon(html: str, page_url: str, limit: int = 4) -> Favicon | None:
    for url in discover_favicon_urls(html, page_url)[:limit]:
        fetched = await fetch_binary(url, MAX_FAVICON_BYTES)
        if not fetched:
            continue
        status, content, content_type = fetched
        if status != 200 or not content or len(content) < 16:
            continue
        width, height, fmt = inspect_image(content)
        if fmt is None and not _is_svg(content, content_type):
            continue  # HTML error page served at /favicon.ico etc.
        return Favicon(
            url=url, content=content, content_type=content_type, width=width, height=height, format=fmt or "SVG"
        )
    return None
