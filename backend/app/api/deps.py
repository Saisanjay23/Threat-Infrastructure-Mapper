"""FastAPI dependencies: database, services, authentication and RBAC."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.security import ROLE_PERMISSIONS, Permission, Role, decode_token, has_permission
from app.db.mongo import get_db
from app.models.user import CurrentUser
from app.pipeline.runner import PipelineRunner
from app.providers.manager import ProviderManager
from app.repositories.users import UserRepository

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token from POST /auth/login")


def db_dep() -> AsyncIOMotorDatabase:
    return get_db()


def providers_dep(request: Request) -> ProviderManager:
    return request.app.state.providers


def runner_dep(request: Request) -> PipelineRunner:
    return request.app.state.runner


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def user_from_token(token: str) -> CurrentUser:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = decode_token(token)
    except jwt.PyJWTError as exc:
        raise unauthorized from exc
    if payload.get("type") != "access":
        raise unauthorized
    user = await UserRepository(get_db()).get(payload.get("sub", ""))
    if user is None or user.get("disabled"):
        raise unauthorized
    role = Role(user["role"])
    return CurrentUser(
        id=user["_id"],
        username=user["username"],
        role=role,
        permissions=sorted(p.value for p in ROLE_PERMISSIONS[role]),
    )


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> CurrentUser:
    if creds is None or not creds.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    return await user_from_token(creds.credentials)


async def get_current_user_or_query(
    request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)
) -> CurrentUser:
    """Allows `?access_token=` for resources loaded by <img> tags and downloads."""
    token = creds.credentials if creds else request.query_params.get("access_token")
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return await user_from_token(token)


def require(permission: Permission) -> Callable[..., Coroutine[Any, Any, CurrentUser]]:
    async def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not has_permission(user.role, permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission.value}")
        return user

    return checker
