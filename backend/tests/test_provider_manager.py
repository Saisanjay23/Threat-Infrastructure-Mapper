"""ProviderManager behaviour: enable/disable, keys, cache, usage accounting, health, daily limits."""

import pytest

from app.models.common import IOCType
from app.providers.manager import ProviderManager
from app.utils.ioc import parse_ioc
from tests.fakes import fake_registry


@pytest.fixture
async def pm(db):
    manager = ProviderManager(db, providers=fake_registry())
    await manager.startup()
    yield manager
    await manager.shutdown()


async def test_defaults_enable_free_providers_without_keys(pm):
    listed = {p.name: p for p in await pm.list_providers()}
    assert listed["fake_free"].enabled is True
    assert listed["fake_key"].enabled is False
    assert listed["fake_key"].health.state == "unconfigured"
    assert [p.name for p in await pm.list_providers()][0] == "fake_free"  # sorted by priority


async def test_cache_hit_avoids_second_call(pm):
    ioc = parse_ioc("example.com")
    first = await pm.run("fake_free", ioc)
    second = await pm.run("fake_free", ioc)
    assert first.ok and not first.cached
    assert second.ok and second.cached
    assert pm.providers["fake_free"].calls == 1
    assert second.result.related[0].value == "203.0.113.10"
    desc = await pm.describe("fake_free")
    assert desc.usage.total_calls == 1
    assert desc.usage.cache_hits == 1
    assert desc.health.state == "healthy"
    assert desc.usage.today_calls == 1


async def test_disabled_provider_is_skipped(pm):
    await pm.update("fake_free", {"enabled": False})
    run = await pm.run("fake_free", parse_ioc("example.com"))
    assert run.skipped and run.error == "disabled"


async def test_unsupported_type_is_skipped(pm):
    run = await pm.run("fake_key", parse_ioc("8.8.8.8"))
    assert run.skipped


async def test_api_key_lifecycle_and_daily_limit(pm):
    await pm.update("fake_key", {"enabled": True})
    assert (await pm.run("fake_key", parse_ioc("a.test"))).error == "API key not configured"
    desc = await pm.set_api_key("fake_key", "secret-key")
    assert desc.has_api_key
    assert desc.api_key_masked == "secr**-key"
    raw = await pm.get_config("fake_key")
    assert "secret-key" not in str(raw)  # encrypted at rest
    assert (await pm.run("fake_key", parse_ioc("a.test"))).ok
    assert (await pm.run("fake_key", parse_ioc("b.test"))).ok
    limited = await pm.run("fake_key", parse_ioc("c.test"))
    assert limited.skipped and "daily limit" in (limited.error or "")
    assert (await pm.describe("fake_key")).usage.credits_used == 2
    removed = await pm.delete_api_key("fake_key")
    assert not removed.has_api_key


async def test_failures_degrade_then_mark_down(pm):
    for _ in range(5):
        run = await pm.run("fake_fail", parse_ioc("example.com"), use_cache=False)
        assert not run.ok and "boom" in (run.error or "")
    desc = await pm.describe("fake_fail")
    assert desc.health.state == "down"
    assert desc.usage.errors == 5
    assert desc.health.consecutive_failures == 5


async def test_eligible_respects_category_priority_and_filters(pm):
    assert await pm.eligible(IOCType.DOMAIN) == ["fake_free", "fake_fail"]
    assert await pm.eligible(IOCType.DOMAIN, category="credit") == []
    assert await pm.eligible(IOCType.DOMAIN, exclude={"fake_fail"}) == ["fake_free"]
    assert await pm.eligible(IOCType.IP) == ["fake_free"]


async def test_pivot_runs_and_caches(pm):
    run = await pm.pivot("fake_free", "favicon_mmh3", "12345")
    assert run.ok and run.result.related[0].value == "pivot-hit.test"
    assert (await pm.pivot("fake_free", "favicon_mmh3", "12345")).cached
    assert (await pm.pivot("fake_free", "title", "x")).skipped
    assert await pm.eligible_pivots("favicon_mmh3", allow_credit=False) == ["fake_free"]


async def test_clear_cache_and_usage_history(pm):
    await pm.run("fake_free", parse_ioc("example.com"))
    assert await pm.clear_cache("fake_free") == 1
    history = await pm.usage_history("fake_free")
    assert history and history[0]["calls"] == 1


async def test_test_endpoint_runs_live(pm):
    result = await pm.test("fake_free")
    assert result.ok and result.message == "OK"
    failing = await pm.test("fake_fail")
    assert not failing.ok and "boom" in failing.message


async def test_set_key_on_keyless_provider_rejected(pm):
    with pytest.raises(ValueError):
        await pm.set_api_key("fake_fail", "x")
