"""Provider abstraction. Every intelligence source implements `BaseProvider`."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal

import aiohttp

from app.models.common import IOCType
from app.models.graph import RelatedEntity
from app.utils.ioc import ParsedIOC

RETRYABLE_STATUS = {502, 503, 504}

PivotKind = Literal[
    "favicon_mmh3", "favicon_sha256", "cert_sha256", "cert_sha1", "title", "tracking_id", "ip", "domain", "asn"
]


class ProviderError(Exception):
    """Generic provider failure."""


class ProviderNotConfiguredError(ProviderError):
    """Provider needs an API key that has not been configured."""


class ProviderRateLimitedError(ProviderError):
    """Provider rejected the call due to quota / rate limits."""


@dataclass
class ProviderContext:
    session: aiohttp.ClientSession
    api_key: str | None = None
    api_secret: str | None = None
    timeout: float = 25.0


@dataclass
class ProviderResult:
    """Normalised provider output."""

    summary: dict[str, Any] = field(default_factory=dict)
    related: list[RelatedEntity] = field(default_factory=list)
    raw: Any = None
    credits_used: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "related": [r.model_dump(mode="json") for r in self.related],
            "raw": self.raw,
            "credits_used": self.credits_used,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProviderResult:
        return cls(
            summary=data.get("summary") or {},
            related=[RelatedEntity.model_validate(r) for r in data.get("related") or []],
            raw=data.get("raw"),
            credits_used=data.get("credits_used", 0),
        )


class BaseProvider(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[Literal["free", "credit"]] = "free"
    supported_types: ClassVar[frozenset[IOCType]] = frozenset()
    supported_pivots: ClassVar[frozenset[str]] = frozenset()
    requires_api_key: ClassVar[bool] = False
    accepts_api_key: ClassVar[bool] = False
    default_priority: ClassVar[int] = 100
    default_cache_ttl_hours: ClassVar[int] = 24
    default_daily_limit: ClassVar[int | None] = None
    docs_url: ClassVar[str | None] = None
    sample_ioc: ClassVar[str] = "example.com"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    @abstractmethod
    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        """Look up a single IOC."""

    async def pivot_search(self, kind: str, value: str, ctx: ProviderContext) -> ProviderResult:
        """Search the provider for infrastructure sharing a fingerprint. Override if supported."""
        raise ProviderError(f"{self.name} does not support pivot '{kind}'")

    async def account_info(self, ctx: ProviderContext) -> dict[str, Any] | None:
        """Optional: key validity / remaining quota, shown by the provider Test button. Must not spend credits."""
        return None

    # ------------------------------------------------------------------ helpers
    async def get_json(
        self,
        ctx: ProviderContext,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        auth: aiohttp.BasicAuth | None = None,
        allow_404: bool = False,
        retries: int = 1,
    ) -> Any:
        timeout = aiohttp.ClientTimeout(total=ctx.timeout)
        for attempt in range(retries + 1):
            async with ctx.session.get(url, headers=headers, params=params, auth=auth, timeout=timeout) as resp:
                if resp.status in RETRYABLE_STATUS and attempt < retries:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                if resp.status == 404 and allow_404:
                    return None
                if resp.status in (401, 403):
                    raise ProviderNotConfiguredError(f"{self.name}: authentication failed (HTTP {resp.status})")
                if resp.status == 429:
                    raise ProviderRateLimitedError(f"{self.name}: rate limited (HTTP 429)")
                if resp.status >= 400:
                    text = " ".join((await resp.text())[:300].split())
                    raise ProviderError(f"{self.name}: HTTP {resp.status}: {text}")
                try:
                    return await resp.json(content_type=None)
                except ValueError as exc:
                    raise ProviderError(f"{self.name}: response was not JSON") from exc
        raise ProviderError(f"{self.name}: exhausted retries")

    async def get_text(
        self,
        ctx: ProviderContext,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 1,
    ) -> str:
        timeout = aiohttp.ClientTimeout(total=ctx.timeout)
        for attempt in range(retries + 1):
            async with ctx.session.get(url, params=params, headers=headers, timeout=timeout) as resp:
                if resp.status in RETRYABLE_STATUS and attempt < retries:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                if resp.status >= 400:
                    raise ProviderError(f"{self.name}: HTTP {resp.status}")
                return await resp.text()
        raise ProviderError(f"{self.name}: exhausted retries")

    def require_key(self, ctx: ProviderContext) -> str:
        if not ctx.api_key:
            raise ProviderNotConfiguredError(f"{self.display_name} requires an API key")
        return ctx.api_key
