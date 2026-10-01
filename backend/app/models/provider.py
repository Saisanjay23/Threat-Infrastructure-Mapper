"""Intelligence provider configuration / status models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ProviderCategory = Literal["free", "credit"]
HealthState = Literal["healthy", "degraded", "down", "unknown", "unconfigured"]


class ProviderUsage(BaseModel):
    total_calls: int = 0
    cache_hits: int = 0
    errors: int = 0
    credits_used: int = 0
    avg_latency_ms: float = 0.0
    last_called: datetime | None = None
    today_calls: int = 0


class ProviderHealth(BaseModel):
    state: HealthState = "unknown"
    last_checked: datetime | None = None
    last_success: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0


class ProviderOut(BaseModel):
    name: str
    display_name: str
    description: str
    category: ProviderCategory
    supported_types: list[str]
    requires_api_key: bool
    has_api_key: bool
    api_key_masked: str | None = None
    enabled: bool
    priority: int
    cache_ttl_hours: int
    daily_limit: int | None = None
    health: ProviderHealth
    usage: ProviderUsage
    docs_url: str | None = None


class ProviderUpdate(BaseModel):
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=1, le=1000)
    cache_ttl_hours: int | None = Field(default=None, ge=0, le=24 * 90)
    daily_limit: int | None = Field(default=None, ge=0)


class ProviderApiKey(BaseModel):
    api_key: str = Field(min_length=1, max_length=512)
    api_secret: str | None = Field(default=None, max_length=512, description="Secondary secret (Censys, FOFA email)")


class ProviderTestResult(BaseModel):
    name: str
    ok: bool
    latency_ms: float
    message: str
    sample: dict[str, Any] | None = None
