"""First-run bootstrap: default administrator account."""

from __future__ import annotations

import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import get_settings
from app.core.security import Role
from app.repositories.users import UserRepository

log = logging.getLogger(__name__)


async def ensure_admin(db: AsyncIOMotorDatabase) -> None:
    settings = get_settings()
    repo = UserRepository(db)
    if await repo.count({"role": Role.ADMIN.value}) > 0:
        return
    await repo.create(
        settings.admin_username, settings.admin_password, Role.ADMIN.value, settings.admin_email, "Administrator"
    )
    log.warning("Created default administrator '%s' - change the password after first login", settings.admin_username)
