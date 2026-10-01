"""Provider Manager: configuration, API keys, priorities, cache, health and usage accounting."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import aiohttp
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import get_settings
from app.core.security import decrypt_secret, encrypt_secret, mask_secret
from app.db.mongo import Collections
from app.models.common import IOCType, utcnow
from app.models.provider import ProviderHealth, ProviderOut, ProviderTestResult, ProviderUsage
from app.providers.base import (
    BaseProvider,
    ProviderContext,
    ProviderError,
    ProviderNotConfiguredError,
    ProviderRateLimitedError,
    ProviderResult,
)
from app.providers.registry import build_providers
from app.utils.ioc import ParsedIOC, parse_ioc

log = logging.getLogger(__name__)


@dataclass
class ProviderRun:
    provider: str
    ok: bool
    cached: bool = False
    skipped: bool = False
    error: str | None = None
    latency_ms: float = 0.0
    result: ProviderResult = field(default_factory=ProviderResult)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "ok": self.ok,
            "cached": self.cached,
            "skipped": self.skipped,
            "error": self.error,
            "latency_ms": round(self.latency_ms, 1),
            "summary": self.result.summary,
            "related_count": len(self.result.related),
        }


def cache_key(provider: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{provider}|{kind}|{value}".encode()).hexdigest()


class ProviderManager:
    def __init__(self, db: AsyncIOMotorDatabase, providers: dict[str, BaseProvider] | None = None) -> None:
        self.db = db
        self.providers = providers or build_providers()
        self._session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()

    # ------------------------------------------------------------------ lifecycle
    async def startup(self) -> None:
        await self.sync_configs()

    async def shutdown(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def session(self) -> aiohttp.ClientSession:
        async with self._session_lock:
            if self._session is None or self._session.closed:
                self._session = aiohttp.ClientSession(
                    headers={"User-Agent": f"TIM/{get_settings().version} (+threat-infrastructure-mapper)"},
                    connector=aiohttp.TCPConnector(limit=50, ttl_dns_cache=300),
                )
            return self._session

    @property
    def _configs(self):
        return self.db[Collections.PROVIDERS]

    async def sync_configs(self) -> None:
        """Insert default configuration for any provider that has none yet."""
        for p in self.providers.values():
            await self._configs.update_one(
                {"_id": p.name},
                {
                    "$setOnInsert": {
                        "_id": p.name,
                        "enabled": not p.requires_api_key and p.category == "free",
                        "priority": p.default_priority,
                        "cache_ttl_hours": p.default_cache_ttl_hours,
                        "daily_limit": p.default_daily_limit,
                        "api_key_enc": None,
                        "api_secret_enc": None,
                        "health": ProviderHealth().model_dump(),
                        "usage": {
                            "total_calls": 0,
                            "cache_hits": 0,
                            "errors": 0,
                            "credits_used": 0,
                            "latency_total_ms": 0.0,
                            "last_called": None,
                        },
                        "created_at": utcnow(),
                    }
                },
                upsert=True,
            )

    async def get_config(self, name: str) -> dict[str, Any]:
        cfg = await self._configs.find_one({"_id": name})
        if cfg is None:
            await self.sync_configs()
            cfg = await self._configs.find_one({"_id": name})
        return cfg or {}

    def get(self, name: str) -> BaseProvider:
        if name not in self.providers:
            raise KeyError(name)
        return self.providers[name]

    # ------------------------------------------------------------------ admin operations
    async def update(self, name: str, fields: dict[str, Any]) -> ProviderOut:
        self.get(name)
        clean = {k: v for k, v in fields.items() if v is not None}
        if clean:
            await self._configs.update_one({"_id": name}, {"$set": {**clean, "updated_at": utcnow()}})
        return await self.describe(name)

    async def set_api_key(self, name: str, api_key: str, api_secret: str | None = None) -> ProviderOut:
        provider = self.get(name)
        if not (provider.requires_api_key or provider.accepts_api_key):
            raise ValueError(f"{provider.display_name} does not use an API key")
        update: dict[str, Any] = {
            "api_key_enc": encrypt_secret(api_key.strip()),
            "updated_at": utcnow(),
            "health.state": "unknown",
            "health.last_error": None,
        }
        update["api_secret_enc"] = encrypt_secret(api_secret.strip()) if api_secret else None
        await self._configs.update_one({"_id": name}, {"$set": update})
        return await self.describe(name)

    async def delete_api_key(self, name: str) -> ProviderOut:
        self.get(name)
        await self._configs.update_one(
            {"_id": name}, {"$set": {"api_key_enc": None, "api_secret_enc": None, "updated_at": utcnow()}}
        )
        return await self.describe(name)

    async def clear_cache(self, name: str | None = None) -> int:
        query = {"provider": name} if name else {}
        result = await self.db[Collections.PROVIDER_CACHE].delete_many(query)
        return result.deleted_count

    def _credentials(self, cfg: dict[str, Any]) -> tuple[str | None, str | None]:
        key = decrypt_secret(cfg["api_key_enc"]) if cfg.get("api_key_enc") else None
        secret = decrypt_secret(cfg["api_secret_enc"]) if cfg.get("api_secret_enc") else None
        return key, secret

    async def _today_calls(self, name: str) -> int:
        doc = await self.db[Collections.PROVIDER_USAGE].find_one(
            {"provider": name, "day": utcnow().strftime("%Y-%m-%d")}
        )
        return int(doc.get("calls", 0)) if doc else 0

    async def describe(self, name: str) -> ProviderOut:
        p = self.get(name)
        cfg = await self.get_config(name)
        key, _ = self._credentials(cfg)
        usage = cfg.get("usage") or {}
        total = int(usage.get("total_calls", 0))
        health = ProviderHealth.model_validate(cfg.get("health") or {})
        if p.requires_api_key and not key:
            health.state = "unconfigured"
        return ProviderOut(
            name=p.name,
            display_name=p.display_name,
            description=p.description,
            category=p.category,
            supported_types=sorted(t.value for t in p.supported_types),
            requires_api_key=p.requires_api_key,
            has_api_key=bool(key),
            api_key_masked=mask_secret(key),
            enabled=bool(cfg.get("enabled")),
            priority=int(cfg.get("priority", p.default_priority)),
            cache_ttl_hours=int(cfg.get("cache_ttl_hours", p.default_cache_ttl_hours)),
            daily_limit=cfg.get("daily_limit"),
            health=health,
            usage=ProviderUsage(
                total_calls=total,
                cache_hits=int(usage.get("cache_hits", 0)),
                errors=int(usage.get("errors", 0)),
                credits_used=int(usage.get("credits_used", 0)),
                avg_latency_ms=round(float(usage.get("latency_total_ms", 0.0)) / total, 1) if total else 0.0,
                last_called=usage.get("last_called"),
                today_calls=await self._today_calls(name),
            ),
            docs_url=p.docs_url,
        )

    async def list_providers(self) -> list[ProviderOut]:
        items = [await self.describe(n) for n in self.providers]
        return sorted(items, key=lambda p: (p.priority, p.name))

    # ------------------------------------------------------------------ accounting
    async def _record(
        self,
        name: str,
        *,
        ok: bool,
        cached: bool,
        latency_ms: float,
        credits: int,
        error: str | None = None,
        health_state: str | None = None,
    ) -> None:
        now = utcnow()
        inc: dict[str, Any] = {}
        set_: dict[str, Any] = {}
        if cached:
            inc["usage.cache_hits"] = 1
        else:
            inc.update({"usage.total_calls": 1, "usage.latency_total_ms": latency_ms, "usage.credits_used": credits})
            set_["usage.last_called"] = now
            set_["health.last_checked"] = now
            if ok:
                set_.update({"health.state": "healthy", "health.last_success": now, "health.consecutive_failures": 0})
            else:
                inc["usage.errors"] = 1
                inc["health.consecutive_failures"] = 1
                set_["health.last_error"] = (error or "")[:500]
                set_["health.state"] = health_state or "degraded"
        update: dict[str, Any] = {"$inc": inc}
        if set_:
            update["$set"] = set_
        await self._configs.update_one({"_id": name}, update)
        if not cached:
            await self.db[Collections.PROVIDER_USAGE].update_one(
                {"provider": name, "day": now.strftime("%Y-%m-%d")},
                {"$inc": {"calls": 1, "errors": 0 if ok else 1, "credits": credits}},
                upsert=True,
            )
        else:
            await self.db[Collections.PROVIDER_USAGE].update_one(
                {"provider": name, "day": now.strftime("%Y-%m-%d")}, {"$inc": {"cache_hits": 1}}, upsert=True
            )
        # Escalate to "down" after repeated failures.
        if not ok and not cached:
            await self._configs.update_one(
                {"_id": name, "health.consecutive_failures": {"$gte": 5}}, {"$set": {"health.state": "down"}}
            )

    async def _cache_get(self, key: str) -> dict[str, Any] | None:
        doc = await self.db[Collections.PROVIDER_CACHE].find_one({"_id": key})
        if doc and doc.get("expires_at") and doc["expires_at"] > utcnow():
            return doc.get("result")
        return None

    async def _cache_set(
        self, key: str, provider: str, kind: str, value: str, result: ProviderResult, ttl_hours: int
    ) -> None:
        if ttl_hours <= 0:
            return
        now = utcnow()
        await self.db[Collections.PROVIDER_CACHE].replace_one(
            {"_id": key},
            {
                "_id": key,
                "provider": provider,
                "kind": kind,
                "value": value,
                "result": result.to_dict(),
                "created_at": now,
                "expires_at": now + timedelta(hours=ttl_hours),
            },
            upsert=True,
        )

    # ------------------------------------------------------------------ execution
    async def _execute(
        self,
        name: str,
        kind: str,
        value: str,
        call: Any,
        *,
        use_cache: bool = True,
        force: bool = False,
    ) -> ProviderRun:
        provider = self.get(name)
        cfg = await self.get_config(name)
        if not cfg.get("enabled") and not force:
            return ProviderRun(provider=name, ok=False, skipped=True, error="disabled")
        key, secret = self._credentials(cfg)
        if provider.requires_api_key and not key:
            return ProviderRun(provider=name, ok=False, skipped=True, error="API key not configured")

        ckey = cache_key(name, kind, value)
        if use_cache:
            cached = await self._cache_get(ckey)
            if cached is not None:
                await self._record(name, ok=True, cached=True, latency_ms=0, credits=0)
                return ProviderRun(provider=name, ok=True, cached=True, result=ProviderResult.from_dict(cached))

        limit = cfg.get("daily_limit")
        if limit is not None and limit > 0 and await self._today_calls(name) >= limit and not force:
            return ProviderRun(provider=name, ok=False, skipped=True, error=f"daily limit of {limit} reached")

        ctx = ProviderContext(
            session=await self.session(),
            api_key=key,
            api_secret=secret,
            timeout=get_settings().provider_timeout_seconds,
        )
        start = time.perf_counter()
        try:
            result: ProviderResult = await asyncio.wait_for(call(provider, ctx), timeout=max(ctx.timeout, 45.0) + 15)
        except ProviderNotConfiguredError as exc:
            latency = (time.perf_counter() - start) * 1000
            await self._record(
                name, ok=False, cached=False, latency_ms=latency, credits=0, error=str(exc), health_state="unconfigured"
            )
            return ProviderRun(provider=name, ok=False, error=str(exc), latency_ms=latency)
        except ProviderRateLimitedError as exc:
            latency = (time.perf_counter() - start) * 1000
            await self._record(name, ok=False, cached=False, latency_ms=latency, credits=0, error=str(exc))
            return ProviderRun(provider=name, ok=False, error=str(exc), latency_ms=latency)
        except (ProviderError, aiohttp.ClientError, TimeoutError, OSError, ValueError) as exc:
            latency = (time.perf_counter() - start) * 1000
            message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            await self._record(name, ok=False, cached=False, latency_ms=latency, credits=0, error=message)
            log.warning("Provider %s failed for %s=%s: %s", name, kind, value, message)
            return ProviderRun(provider=name, ok=False, error=message, latency_ms=latency)
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            message = f"{type(exc).__name__}: {exc}"
            await self._record(name, ok=False, cached=False, latency_ms=latency, credits=0, error=message)
            log.exception("Unexpected provider error in %s", name)
            return ProviderRun(provider=name, ok=False, error=message, latency_ms=latency)

        latency = (time.perf_counter() - start) * 1000
        await self._record(name, ok=True, cached=False, latency_ms=latency, credits=result.credits_used)
        await self._cache_set(
            ckey, name, kind, value, result, int(cfg.get("cache_ttl_hours", provider.default_cache_ttl_hours))
        )
        return ProviderRun(provider=name, ok=True, latency_ms=latency, result=result)

    async def run(self, name: str, ioc: ParsedIOC, *, use_cache: bool = True, force: bool = False) -> ProviderRun:
        provider = self.get(name)
        if not provider.supports(ioc.type):
            return ProviderRun(provider=name, ok=False, skipped=True, error=f"does not support {ioc.type}")

        async def call(p: BaseProvider, ctx: ProviderContext) -> ProviderResult:
            return await p.query(ioc, ctx)

        return await self._execute(name, str(ioc.type), ioc.value, call, use_cache=use_cache, force=force)

    async def pivot(self, name: str, kind: str, value: str, *, use_cache: bool = True) -> ProviderRun:
        provider = self.get(name)
        if kind not in provider.supported_pivots:
            return ProviderRun(provider=name, ok=False, skipped=True, error=f"pivot {kind} unsupported")

        async def call(p: BaseProvider, ctx: ProviderContext) -> ProviderResult:
            return await p.pivot_search(kind, value, ctx)

        return await self._execute(name, f"pivot:{kind}", value, call, use_cache=use_cache)

    async def eligible(
        self,
        ioc_type: IOCType,
        *,
        category: str | None = None,
        names: list[str] | None = None,
        exclude: set[str] | None = None,
    ) -> list[str]:
        out: list[tuple[int, str]] = []
        for name, p in self.providers.items():
            if names and name not in names:
                continue
            if exclude and name in exclude:
                continue
            if category and p.category != category:
                continue
            if not p.supports(ioc_type):
                continue
            cfg = await self.get_config(name)
            if not cfg.get("enabled"):
                continue
            out.append((int(cfg.get("priority", p.default_priority)), name))
        return [n for _, n in sorted(out)]

    async def eligible_pivots(self, kind: str, *, allow_credit: bool) -> list[str]:
        out: list[tuple[int, str]] = []
        for name, p in self.providers.items():
            if kind not in p.supported_pivots or (p.category == "credit" and not allow_credit):
                continue
            cfg = await self.get_config(name)
            if cfg.get("enabled"):
                out.append((int(cfg.get("priority", p.default_priority)), name))
        return [n for _, n in sorted(out)]

    async def run_many(self, names: list[str], ioc: ParsedIOC, *, concurrency: int = 6) -> list[ProviderRun]:
        sem = asyncio.Semaphore(concurrency)

        async def one(n: str) -> ProviderRun:
            async with sem:
                return await self.run(n, ioc)

        return list(await asyncio.gather(*(one(n) for n in names)))

    async def test(self, name: str) -> ProviderTestResult:
        provider = self.get(name)
        account: dict[str, Any] | None = None
        cfg = await self.get_config(name)
        key, secret = self._credentials(cfg)
        if key or not provider.requires_api_key:
            ctx = ProviderContext(
                session=await self.session(),
                api_key=key,
                api_secret=secret,
                timeout=get_settings().provider_timeout_seconds,
            )
            try:
                account = await provider.account_info(ctx)
            except (ProviderError, aiohttp.ClientError, TimeoutError) as exc:
                account = {"error": str(exc)}
        run = await self.run(name, parse_ioc(provider.sample_ioc), use_cache=False, force=True)
        message = "OK" if run.ok else (run.error or "failed")
        if account and account.get("advice"):
            message = f"{message} - {account['advice']}"
        sample = {k: run.result.summary[k] for k in list(run.result.summary)[:8]} if run.ok else {}
        if account:
            sample["account"] = account
        return ProviderTestResult(
            name=name, ok=run.ok, latency_ms=round(run.latency_ms, 1), message=message, sample=sample or None
        )

    async def usage_history(self, name: str | None = None, days: int = 30) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"day": {"$gte": (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")}}
        if name:
            query["provider"] = name
        docs = await self.db[Collections.PROVIDER_USAGE].find(query, {"_id": 0}).sort("day", 1).to_list(length=5000)
        return docs
