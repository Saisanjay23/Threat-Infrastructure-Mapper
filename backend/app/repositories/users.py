"""User repository."""

from __future__ import annotations

from app.core.security import hash_password
from app.db.mongo import Collections
from app.models.common import new_id, utcnow
from app.repositories.base import Doc, Repository


class UserRepository(Repository):
    collection_name = Collections.USERS

    async def by_username(self, username: str) -> Doc | None:
        return await self.col.find_one({"username": username.lower()})

    async def create(
        self, username: str, password: str, role: str, email: str | None = None, full_name: str | None = None
    ) -> Doc:
        doc: Doc = {
            "_id": new_id("usr_"),
            "username": username.lower(),
            "password_hash": hash_password(password),
            "role": role,
            "full_name": full_name,
            "disabled": False,
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "last_login": None,
        }
        if email:
            doc["email"] = email.lower()
        await self.col.insert_one(doc)
        return doc
