"""Shared model primitives and enumerations."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Generic, TypeVar

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

T = TypeVar("T")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex
    return f"{prefix}{raw}" if prefix else raw


class IOCType(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CERTIFICATE = "certificate"


class AssetType(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CERTIFICATE = "certificate"
    ANALYTICS = "analytics"
    PIXEL = "pixel"
    TRACKING = "tracking"
    FAVICON = "favicon"
    LOGO = "logo"
    ASN = "asn"
    HOSTING = "hosting"
    NAMESERVER = "nameserver"
    CLUSTER = "cluster"


class SiteStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    PARKED = "PARKED"
    TAKEDOWN = "TAKEDOWN"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(StrEnum):
    VERY_HIGH = "Very High"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MongoModel(BaseModel):
    """Base for documents read from MongoDB: accepts `_id` and exposes it as `id`."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str = Field(validation_alias=AliasChoices("_id", "id"))


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class Message(BaseModel):
    message: str
    detail: dict[str, Any] | None = None
