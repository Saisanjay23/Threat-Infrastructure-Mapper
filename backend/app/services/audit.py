"""Audit trail writer."""

from __future__ import annotations

import logging
from typing import Any

from app.db.mongo import Collections, get_db
from app.models.common import new_id, utcnow

log = logging.getLogger(__name__)


async def audit(
    action: str,
    *,
    username: str | None = None,
    role: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip: str | None = None,
    status: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    """Record an audit event. Never raises: auditing must not break the request."""
    try:
        await get_db()[Collections.AUDIT_LOGS].insert_one(
            {
                "_id": new_id("aud_"),
                "timestamp": utcnow(),
                "username": username,
                "role": role,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "ip": ip,
                "status": status,
                "details": details or {},
            }
        )
    except Exception:
        log.exception("Failed to write audit log for action %s", action)
