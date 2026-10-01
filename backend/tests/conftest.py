"""Shared fixtures. Tests run against a real local MongoDB using an isolated `tim_test` database."""

from __future__ import annotations

import os

os.environ["TIM_ENVIRONMENT"] = "test"
os.environ["TIM_MONGO_DB"] = os.environ.get("TIM_TEST_MONGO_DB", "tim_test")
os.environ["TIM_SECRET_KEY"] = "test-secret-key-that-is-long-enough-0123456789"
os.environ["TIM_ADMIN_USERNAME"] = "admin"
os.environ["TIM_ADMIN_PASSWORD"] = "AdminPass!123"
os.environ["TIM_SCREENSHOTS_ENABLED"] = "false"

from collections.abc import AsyncIterator

import httpx
import pytest
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import get_settings

get_settings.cache_clear()

from app.db.mongo import Mongo  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session")
async def app() -> AsyncIterator:
    application = create_app()
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture(scope="session")
async def db(app) -> AsyncIOMotorDatabase:
    return Mongo.get_db()


@pytest.fixture(autouse=True)
async def clean_db(db: AsyncIOMotorDatabase) -> AsyncIterator[None]:
    """Each test starts with empty data collections (users/providers are preserved)."""
    for name in (
        "investigations",
        "assets",
        "artifacts",
        "relationships",
        "clusters",
        "cases",
        "audit_logs",
        "reports",
        "provider_cache",
        "provider_usage",
        "files.files",
        "files.chunks",
        "settings",
    ):
        await db[name].delete_many({})
    await db["users"].delete_many({"username": {"$ne": "admin"}})
    await db["providers"].delete_many({})
    from app.api.routes.auth import _FAILED

    _FAILED.clear()
    yield


@pytest.fixture
async def manager(app):
    m = app.state.providers
    await m.sync_configs()
    return m


@pytest.fixture
async def client(app, manager) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def login(client: httpx.AsyncClient, username: str = "admin", password: str = "AdminPass!123") -> dict[str, str]:
    resp = await client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture
async def admin_headers(client: httpx.AsyncClient) -> dict[str, str]:
    return await login(client)


@pytest.fixture
async def make_user(client: httpx.AsyncClient, admin_headers: dict[str, str]):
    async def _make(username: str, role: str, password: str = "UserPass!123") -> dict[str, str]:
        resp = await client.post(
            "/users", headers=admin_headers, json={"username": username, "password": password, "role": role}
        )
        assert resp.status_code == 201, resp.text
        return await login(client, username, password)

    return _make
