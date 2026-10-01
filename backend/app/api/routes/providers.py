"""Provider management: enable/disable, priorities, API keys, health tests, usage and cache."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import client_ip, providers_dep, require
from app.core.security import Permission
from app.models.common import Message
from app.models.provider import ProviderApiKey, ProviderOut, ProviderTestResult, ProviderUpdate
from app.models.user import CurrentUser
from app.providers.manager import ProviderManager
from app.services.audit import audit

router = APIRouter(prefix="/providers", tags=["Providers"])


def _known(manager: ProviderManager, name: str) -> None:
    if name not in manager.providers:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown provider '{name}'")


@router.get("", response_model=list[ProviderOut], summary="All providers with health and usage")
async def list_providers(
    _: CurrentUser = Depends(require(Permission.PROVIDER_READ)), manager: ProviderManager = Depends(providers_dep)
) -> list[ProviderOut]:
    return await manager.list_providers()


@router.get("/usage", summary="Daily usage history (calls, cache hits, errors, credits)")
async def usage(
    provider: str | None = None,
    days: int = Query(30, ge=1, le=365),
    _: CurrentUser = Depends(require(Permission.PROVIDER_READ)),
    manager: ProviderManager = Depends(providers_dep),
) -> list[dict[str, Any]]:
    return await manager.usage_history(provider, days)


@router.get("/{name}", response_model=ProviderOut, summary="One provider")
async def get_provider(
    name: str,
    _: CurrentUser = Depends(require(Permission.PROVIDER_READ)),
    manager: ProviderManager = Depends(providers_dep),
) -> ProviderOut:
    _known(manager, name)
    return await manager.describe(name)


@router.patch("/{name}", response_model=ProviderOut, summary="Enable/disable, set priority, cache TTL, daily limit")
async def update_provider(
    name: str,
    body: ProviderUpdate,
    request: Request,
    user: CurrentUser = Depends(require(Permission.PROVIDER_ADMIN)),
    manager: ProviderManager = Depends(providers_dep),
) -> ProviderOut:
    _known(manager, name)
    out = await manager.update(name, body.model_dump(exclude_none=True))
    await audit(
        "provider.update",
        username=user.username,
        role=user.role,
        resource_type="provider",
        resource_id=name,
        ip=client_ip(request),
        details=body.model_dump(exclude_none=True),
    )
    return out


@router.put("/{name}/api-key", response_model=ProviderOut, summary="Store an API key (encrypted at rest)")
async def set_api_key(
    name: str,
    body: ProviderApiKey,
    request: Request,
    user: CurrentUser = Depends(require(Permission.PROVIDER_ADMIN)),
    manager: ProviderManager = Depends(providers_dep),
) -> ProviderOut:
    _known(manager, name)
    try:
        out = await manager.set_api_key(name, body.api_key, body.api_secret)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await audit(
        "provider.api_key.set",
        username=user.username,
        role=user.role,
        resource_type="provider",
        resource_id=name,
        ip=client_ip(request),
    )
    return out


@router.delete("/{name}/api-key", response_model=ProviderOut, summary="Remove a stored API key")
async def delete_api_key(
    name: str,
    request: Request,
    user: CurrentUser = Depends(require(Permission.PROVIDER_ADMIN)),
    manager: ProviderManager = Depends(providers_dep),
) -> ProviderOut:
    _known(manager, name)
    out = await manager.delete_api_key(name)
    await audit(
        "provider.api_key.delete",
        username=user.username,
        role=user.role,
        resource_type="provider",
        resource_id=name,
        ip=client_ip(request),
    )
    return out


@router.post("/{name}/test", response_model=ProviderTestResult, summary="Live health check against a sample IOC")
async def test_provider(
    name: str,
    user: CurrentUser = Depends(require(Permission.PROVIDER_ADMIN)),
    manager: ProviderManager = Depends(providers_dep),
) -> ProviderTestResult:
    _known(manager, name)
    result = await manager.test(name)
    await audit(
        "provider.test",
        username=user.username,
        role=user.role,
        resource_type="provider",
        resource_id=name,
        status="success" if result.ok else "failure",
        details={"message": result.message},
    )
    return result


@router.post("/{name}/cache/clear", response_model=Message, summary="Purge cached responses for one provider")
async def clear_cache(
    name: str,
    user: CurrentUser = Depends(require(Permission.PROVIDER_ADMIN)),
    manager: ProviderManager = Depends(providers_dep),
) -> Message:
    _known(manager, name)
    removed = await manager.clear_cache(name)
    await audit(
        "provider.cache.clear",
        username=user.username,
        role=user.role,
        resource_type="provider",
        resource_id=name,
        details={"removed": removed},
    )
    return Message(message=f"Removed {removed} cached response(s)", detail={"removed": removed})
