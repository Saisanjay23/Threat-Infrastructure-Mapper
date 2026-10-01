"""Investigation workflow models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.common import IOCType, MongoModel


class InvestigationStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StageName(StrEnum):
    COLLECTION = "collection"
    ENRICHMENT = "enrichment"
    PIVOT = "pivot"
    CORRELATION = "correlation"


STAGE_ORDER: list[StageName] = [
    StageName.COLLECTION,
    StageName.ENRICHMENT,
    StageName.PIVOT,
    StageName.CORRELATION,
]


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


CreditPolicy = Literal["never", "when_needed", "always"]


class InvestigationOptions(BaseModel):
    screenshots: bool = Field(default=True, description="Capture desktop/mobile/full-page screenshots")
    credit_policy: CreditPolicy = Field(
        default="when_needed",
        description="never: free sources only; when_needed: credit sources only if free sources yield "
        "too little; always: query every enabled credit source",
    )
    providers: list[str] | None = Field(default=None, description="Restrict to these provider names")
    expand_pivots: bool = Field(default=True, description="Investigate related domains discovered by pivots")
    max_pivot_assets: int = Field(default=15, ge=0, le=200)
    brand: str | None = Field(default=None, max_length=128, description="Brand to test impersonation against")
    brand_domains: list[str] = Field(default_factory=list, description="Legitimate brand domains")
    notes: str | None = Field(default=None, max_length=5000)


class InvestigationCreate(BaseModel):
    ioc: str = Field(min_length=1, max_length=2048, examples=["example.com"])
    options: InvestigationOptions = Field(default_factory=InvestigationOptions)
    tags: list[str] = Field(default_factory=list)
    case_id: str | None = None


class BulkInvestigationCreate(BaseModel):
    iocs: list[str] = Field(min_length=1, max_length=500)
    options: InvestigationOptions = Field(default_factory=InvestigationOptions)
    tags: list[str] = Field(default_factory=list)
    case_id: str | None = None


class StageEvent(BaseModel):
    timestamp: datetime
    level: Literal["info", "warning", "error"] = "info"
    message: str


class StageState(BaseModel):
    status: StageStatus = StageStatus.PENDING
    progress: int = 0
    message: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    events: list[StageEvent] = Field(default_factory=list)


class InvestigationSummary(BaseModel):
    assets_discovered: int = 0
    domains: int = 0
    ips: int = 0
    certificates: int = 0
    tracking_ids: int = 0
    relationships: int = 0
    clusters: int = 0
    high_confidence: int = 0
    site_status: str | None = None
    impersonation_score: int | None = None
    max_confidence: int = 0


class InvestigationOut(MongoModel):
    ioc: str
    ioc_type: IOCType
    normalized: str
    status: InvestigationStatus
    options: InvestigationOptions
    stages: dict[str, StageState]
    summary: InvestigationSummary = Field(default_factory=InvestigationSummary)
    root_asset_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    case_id: str | None = None
    bulk_id: str | None = None
    cluster_ids: list[str] = Field(default_factory=list)
    created_by: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    notes: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationListItem(MongoModel):
    ioc: str
    ioc_type: IOCType
    status: InvestigationStatus
    summary: InvestigationSummary = Field(default_factory=InvestigationSummary)
    tags: list[str] = Field(default_factory=list)
    created_by: str
    created_at: datetime
    finished_at: datetime | None = None


class BulkInvestigationOut(BaseModel):
    bulk_id: str
    investigation_ids: list[str]
    rejected: list[dict[str, str]]


class InvestigationNote(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
