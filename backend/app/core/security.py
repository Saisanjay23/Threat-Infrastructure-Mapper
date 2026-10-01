"""Password hashing, JWT handling, secret encryption and RBAC permission model."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(StrEnum):
    INVESTIGATION_READ = "investigation:read"
    INVESTIGATION_WRITE = "investigation:write"
    ASSET_READ = "asset:read"
    CASE_READ = "case:read"
    CASE_WRITE = "case:write"
    REPORT_EXPORT = "report:export"
    UPLOAD = "upload:write"
    PROVIDER_READ = "provider:read"
    PROVIDER_ADMIN = "provider:admin"
    SETTINGS_ADMIN = "settings:admin"
    USER_ADMIN = "user:admin"
    AUDIT_READ = "audit:read"


_VIEWER = {
    Permission.INVESTIGATION_READ,
    Permission.ASSET_READ,
    Permission.CASE_READ,
    Permission.PROVIDER_READ,
}
_ANALYST = _VIEWER | {
    Permission.INVESTIGATION_WRITE,
    Permission.CASE_WRITE,
    Permission.REPORT_EXPORT,
    Permission.UPLOAD,
}
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: _VIEWER,
    Role.ANALYST: _ANALYST,
    Role.ADMIN: set(Permission),
}


def has_permission(role: str, permission: Permission) -> bool:
    try:
        return permission in ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return False


# --------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except ValueError:
        return False


# --------------------------------------------------------------------------- JWT
def create_access_token(subject: str, role: str, extra: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


# --------------------------------------------------------------------------- secret encryption
def _fernet() -> Fernet:
    digest = hashlib.sha256(get_settings().secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def mask_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
