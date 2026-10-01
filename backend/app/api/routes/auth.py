"""Authentication and user administration."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pymongo.errors import DuplicateKeyError

from app.api.deps import client_ip, db_dep, get_current_user, require
from app.core.config import get_settings
from app.core.security import Permission, create_access_token, hash_password, verify_password
from app.models.common import Message, utcnow
from app.models.user import CurrentUser, LoginRequest, TokenResponse, UserCreate, UserOut, UserUpdate
from app.repositories.users import UserRepository
from app.services.audit import audit

router = APIRouter(tags=["Authentication"])
users_router = APIRouter(prefix="/users", tags=["Users"])

_FAILED: dict[str, deque[float]] = defaultdict(deque)
MAX_FAILURES = 10
WINDOW_SECONDS = 15 * 60


def _throttle_key(request: Request, username: str) -> str:
    return f"{client_ip(request)}|{username.lower()}"


def _check_throttle(key: str) -> None:
    attempts = _FAILED[key]
    now = time.monotonic()
    while attempts and now - attempts[0] > WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= MAX_FAILURES:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed login attempts; try again later")


@router.post("/auth/login", response_model=TokenResponse, summary="Obtain a JWT access token")
async def login(body: LoginRequest, request: Request, db=Depends(db_dep)) -> TokenResponse:
    key = _throttle_key(request, body.username)
    _check_throttle(key)
    repo = UserRepository(db)
    user = await repo.by_username(body.username)
    if user is None or user.get("disabled") or not verify_password(body.password, user["password_hash"]):
        _FAILED[key].append(time.monotonic())
        await audit("auth.login", username=body.username.lower(), ip=client_ip(request), status="failure")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    _FAILED.pop(key, None)
    await repo.update(user["_id"], {"last_login": utcnow()})
    token = create_access_token(user["_id"], user["role"])
    await audit("auth.login", username=user["username"], role=user["role"], ip=client_ip(request))
    return TokenResponse(
        access_token=token, expires_in=get_settings().access_token_minutes * 60, user=UserOut.model_validate(user)
    )


@router.get("/auth/me", response_model=CurrentUser, summary="Current user and permissions")
async def me(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    return user


@users_router.get("", response_model=list[UserOut], summary="List users")
async def list_users(_: CurrentUser = Depends(require(Permission.USER_ADMIN)), db=Depends(db_dep)) -> list[UserOut]:
    items, _total = await UserRepository(db).find_page({}, sort=[("username", 1)], limit=500)
    return [UserOut.model_validate(u) for u in items]


@users_router.post("", response_model=UserOut, status_code=201, summary="Create a user")
async def create_user(
    body: UserCreate, request: Request, admin: CurrentUser = Depends(require(Permission.USER_ADMIN)), db=Depends(db_dep)
) -> UserOut:
    try:
        doc = await UserRepository(db).create(body.username, body.password, body.role.value, body.email, body.full_name)
    except DuplicateKeyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username or email already exists") from exc
    await audit(
        "user.create",
        username=admin.username,
        role=admin.role,
        resource_type="user",
        resource_id=doc["_id"],
        ip=client_ip(request),
        details={"new_user": body.username, "role": body.role},
    )
    return UserOut.model_validate(doc)


@users_router.patch("/{user_id}", response_model=UserOut, summary="Update a user")
async def update_user(
    user_id: str,
    body: UserUpdate,
    request: Request,
    admin: CurrentUser = Depends(require(Permission.USER_ADMIN)),
    db=Depends(db_dep),
) -> UserOut:
    repo = UserRepository(db)
    fields = body.model_dump(exclude_none=True)
    if "password" in fields:
        fields["password_hash"] = hash_password(fields.pop("password"))
    if user_id == admin.id and (fields.get("disabled") or fields.get("role") not in (None, "admin")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot demote or disable your own account")
    doc = await repo.update(user_id, fields)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    await audit(
        "user.update",
        username=admin.username,
        role=admin.role,
        resource_type="user",
        resource_id=user_id,
        ip=client_ip(request),
        details={k: v for k, v in fields.items() if k != "password_hash"},
    )
    return UserOut.model_validate(doc)


@users_router.delete("/{user_id}", response_model=Message, summary="Delete a user")
async def delete_user(
    user_id: str, request: Request, admin: CurrentUser = Depends(require(Permission.USER_ADMIN)), db=Depends(db_dep)
) -> Message:
    if user_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete your own account")
    if not await UserRepository(db).delete(user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    await audit(
        "user.delete",
        username=admin.username,
        role=admin.role,
        resource_type="user",
        resource_id=user_id,
        ip=client_ip(request),
    )
    return Message(message="User deleted")
