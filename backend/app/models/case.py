"""Case management and reporting models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.models.common import MongoModel, Severity

CaseStatus = Literal["open", "in_progress", "closed"]


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    severity: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list, max_length=50)
    assignee: str | None = Field(default=None, max_length=64)
    asset_ids: list[str] = Field(default_factory=list, max_length=5000)
    investigation_ids: list[str] = Field(default_factory=list, max_length=500)
    cluster_ids: list[str] = Field(default_factory=list, max_length=200)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    severity: Severity | None = None
    status: CaseStatus | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    assignee: str | None = Field(default=None, max_length=64)


class CaseLinks(BaseModel):
    asset_ids: list[str] = Field(default_factory=list, max_length=5000)
    investigation_ids: list[str] = Field(default_factory=list, max_length=500)
    cluster_ids: list[str] = Field(default_factory=list, max_length=200)


class CaseNote(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class CaseOut(MongoModel):
    title: str
    description: str | None = None
    severity: Severity
    status: CaseStatus
    tags: list[str] = Field(default_factory=list)
    assignee: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    investigation_ids: list[str] = Field(default_factory=list)
    cluster_ids: list[str] = Field(default_factory=list)
    notes: list[dict[str, Any]] = Field(default_factory=list)
    created_by: str
    created_at: datetime
    updated_at: datetime


class CaseListItem(MongoModel):
    title: str
    severity: Severity
    status: CaseStatus
    tags: list[str] = Field(default_factory=list)
    assignee: str | None = None
    asset_count: int = 0
    investigation_count: int = 0
    cluster_count: int = 0
    created_by: str
    created_at: datetime
    updated_at: datetime


ReportSection = Literal[
    "executive_summary",
    "investigation_details",
    "evidence",
    "screenshots",
    "threat_clusters",
    "related_assets",
    "confidence_scores",
    "graph_snapshot",
    "analyst_notes",
]
ALL_SECTIONS: list[str] = [
    "executive_summary",
    "investigation_details",
    "evidence",
    "screenshots",
    "threat_clusters",
    "related_assets",
    "confidence_scores",
    "graph_snapshot",
    "analyst_notes",
]


class ExportRequest(BaseModel):
    investigation_id: str | None = None
    cluster_id: str | None = None
    case_id: str | None = None
    asset_ids: list[str] | None = Field(default=None, max_length=5000)
    title: str | None = Field(default=None, max_length=200)
    sections: list[ReportSection] = Field(default_factory=lambda: list(ALL_SECTIONS))  # type: ignore[arg-type]
    min_confidence: int = Field(default=0, ge=0, le=100)
    max_assets: int = Field(default=500, ge=1, le=10000)
    max_screenshots: int = Field(default=12, ge=0, le=60)
    analyst_notes: str | None = Field(default=None, max_length=20000)
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] = "AMBER"
    save: bool = Field(default=True, description="Keep a copy in the report library")

    @model_validator(mode="after")
    def _one_scope(self) -> ExportRequest:
        scopes = [s for s in (self.investigation_id, self.cluster_id, self.case_id) if s]
        if len(scopes) > 1:
            raise ValueError("choose one of investigation_id, cluster_id or case_id")
        if not scopes and not self.asset_ids:
            raise ValueError("an investigation_id, cluster_id, case_id or asset_ids is required")
        return self


class ReportOut(MongoModel):
    title: str
    format: str
    scope_type: str
    scope_id: str | None = None
    size: int
    file_id: str
    filename: str
    sections: list[str] = Field(default_factory=list)
    tlp: str
    created_by: str
    created_at: datetime
