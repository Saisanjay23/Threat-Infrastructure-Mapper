"""Deterministic fake providers for offline tests."""

from __future__ import annotations

from app.models.common import IOCType
from app.models.graph import RelatedEntity, RelationType
from app.providers.base import BaseProvider, ProviderContext, ProviderError, ProviderResult
from app.utils.ioc import ParsedIOC


class FakeFreeProvider(BaseProvider):
    name = "fake_free"
    display_name = "Fake Free"
    description = "test provider"
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.IP})
    supported_pivots = frozenset({"favicon_mmh3"})
    default_priority = 5
    sample_ioc = "example.com"

    def __init__(self) -> None:
        self.calls = 0

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        self.calls += 1
        return ProviderResult(
            summary={"value": ioc.value, "calls": self.calls},
            related=[RelatedEntity(type="ip", value="203.0.113.10", relation=RelationType.RESOLVES_TO)],
            raw={"ok": True},
        )

    async def pivot_search(self, kind: str, value: str, ctx: ProviderContext) -> ProviderResult:
        return ProviderResult(
            summary={"kind": kind},
            related=[RelatedEntity(type="domain", value="pivot-hit.test", relation=RelationType.SHARES_FAVICON)],
        )


class FakeKeyProvider(BaseProvider):
    name = "fake_key"
    display_name = "Fake Keyed"
    description = "requires key"
    category = "credit"
    supported_types = frozenset({IOCType.DOMAIN})
    requires_api_key = True
    accepts_api_key = True
    default_priority = 50
    default_daily_limit = 2

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        assert ctx.api_key == "secret-key"
        return ProviderResult(summary={"keyed": True}, credits_used=1)


class FailingProvider(BaseProvider):
    name = "fake_fail"
    display_name = "Always fails"
    description = "errors"
    category = "free"
    supported_types = frozenset({IOCType.DOMAIN})
    default_priority = 6

    async def query(self, ioc: ParsedIOC, ctx: ProviderContext) -> ProviderResult:
        raise ProviderError("boom")


def fake_registry() -> dict[str, BaseProvider]:
    return {p.name: p for p in (FakeFreeProvider(), FakeKeyProvider(), FailingProvider())}
