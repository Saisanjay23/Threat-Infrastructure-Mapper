"""Audit log models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.models.common import MongoModel


class AuditLogOut(MongoModel):
    timestamp: datetime
    username: str | None = None
    role: str | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    ip: str | None = None
    status: str = "success"
    details: dict[str, Any] | None = None
