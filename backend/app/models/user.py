"""User and authentication models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.core.security import Role
from app.models.common import MongoModel


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=128)
    password: str = Field(min_length=8, max_length=128)
    role: Role = Role.ANALYST


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=128)
    role: Role | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserOut(MongoModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    role: Role
    disabled: bool = False
    created_at: datetime
    last_login: datetime | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class CurrentUser(BaseModel):
    id: str
    username: str
    role: Role
    permissions: list[str]
