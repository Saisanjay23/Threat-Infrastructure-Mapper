"""Command line utilities: `python -m app.cli <command>`.

Commands:
  db-setup         verify MongoDB, create indexes, bootstrap admin user and provider configuration
  create-user      create a user:  create-user <username> <password> [admin|analyst|viewer]
  reset-password   reset a user's password:  reset-password <username> <new-password>
"""

from __future__ import annotations

import asyncio
import sys

from app.core.config import get_settings
from app.core.security import Role, hash_password
from app.db.mongo import Mongo
from app.providers.manager import ProviderManager
from app.repositories.users import UserRepository
from app.services.bootstrap import ensure_admin


async def db_setup() -> int:
    settings = get_settings()
    print(f"Connecting to {settings.mongo_uri} (database '{settings.mongo_db}') ...")
    try:
        db = await Mongo.connect()
    except Exception as exc:
        print(f"ERROR: cannot reach MongoDB: {exc}")
        print("Make sure the 'MongoDB' Windows service is running (services.msc) or run mongod manually.")
        return 1
    info = await Mongo.client.server_info()  # type: ignore[union-attr]
    print(f"MongoDB {info.get('version')} reachable. Indexes ensured.")
    await ensure_admin(db)
    manager = ProviderManager(db)
    await manager.sync_configs()
    await manager.shutdown()
    counts = {name: await db[name].estimated_document_count() for name in sorted(await db.list_collection_names())}
    for name, n in counts.items():
        print(f"  {name:<22} {n:>8}")
    print(f"Default admin user: '{settings.admin_username}' (password from TIM_ADMIN_PASSWORD in backend\\.env)")
    await Mongo.close()
    return 0


async def create_user_in(db, username: str, password: str, role: str = "analyst") -> bool:
    repo = UserRepository(db)
    if await repo.by_username(username):
        print(f"User '{username}' already exists")
        return False
    await repo.create(username, password, Role(role).value)
    print(f"Created {role} '{username}'")
    return True


async def reset_password_in(db, username: str, password: str) -> bool:
    repo = UserRepository(db)
    user = await repo.by_username(username)
    if not user:
        print(f"No such user '{username}'")
        return False
    await repo.update(user["_id"], {"password_hash": hash_password(password), "disabled": False})
    print(f"Password reset for '{username}'")
    return True


async def _with_db(fn, *args: str) -> int:
    db = await Mongo.connect()
    try:
        return 0 if await fn(db, *args) else 1
    finally:
        await Mongo.close()


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print(__doc__)
        return 0
    cmd, args = argv[0], argv[1:]
    if cmd == "db-setup":
        return asyncio.run(db_setup())
    if cmd == "create-user" and len(args) >= 2:
        return asyncio.run(_with_db(create_user_in, *args[:3]))
    if cmd == "reset-password" and len(args) == 2:
        return asyncio.run(_with_db(reset_password_in, *args))
    if cmd == "seed":
        from app.seed import run_seed

        return asyncio.run(run_seed(reset="--reset" in args))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
