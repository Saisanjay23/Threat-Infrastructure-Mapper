"""Threat cluster models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.common import MongoModel


class ClusterListItem(MongoModel):
    name: str
    confidence: int
    confidence_level: str
    severity: str
    counts: dict[str, int] = Field(default_factory=dict)
    status_breakdown: dict[str, int] = Field(default_factory=dict)
    brands: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    investigation_ids: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ClusterOut(ClusterListItem):
    asset_ids: list[str] = Field(default_factory=list)
    fingerprint_ids: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    certificates: list[str] = Field(default_factory=list)
    favicons: list[str] = Field(default_factory=list)
    tracking_ids: list[str] = Field(default_factory=list)
    logos: list[str] = Field(default_factory=list)
    notes: list[dict[str, Any]] = Field(default_factory=list)


class ClusterUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    tags: list[str] | None = Field(default=None, max_length=50)
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")


class ClusterNote(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
