"""Asset (discovered infrastructure entity) and artifact models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.common import AssetType, MongoModel, SiteStatus


class AssetOut(MongoModel):
    type: AssetType
    value: str
    status: SiteStatus = SiteStatus.UNKNOWN
    attributes: dict[str, Any] = Field(default_factory=dict)
    fingerprints: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    investigation_ids: list[str] = Field(default_factory=list)
    cluster_ids: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    confidence: int | None = None
    impersonation_score: int | None = None
    brand_similarity_score: int | None = None
    confidence_level: str | None = None
    correlation: dict[str, Any] = Field(default_factory=dict, description="Per-investigation correlation evidence")
    is_root: bool | None = None
    first_seen: datetime
    last_seen: datetime


class AssetListItem(MongoModel):
    type: AssetType
    value: str
    status: SiteStatus = SiteStatus.UNKNOWN
    confidence: int | None = None
    impersonation_score: int | None = None
    brand_similarity_score: int | None = None
    confidence_level: str | None = None
    sources: list[str] = Field(default_factory=list)
    cluster_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime


class ArtifactOut(MongoModel):
    investigation_id: str | None = None
    asset_id: str | None = None
    kind: str
    content_type: str | None = None
    size: int | None = None
    sha256: str | None = None
    file_id: str | None = None
    data: Any = None
    created_at: datetime


class AssetTagUpdate(BaseModel):
    tags: list[str] = Field(default_factory=list, max_length=50)
