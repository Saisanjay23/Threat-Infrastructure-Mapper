"""WebSockets, asset routes, GridFS file serving, seed dataset, CLI helpers, progress hub, investigation endpoints."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import WebSocketDisconnect

from app.api.routes import ws as ws_routes
from app.cli import create_user_in, reset_password_in
from app.cli import main as cli_main
from app.core.security import create_access_token
from app.db.mongo import get_fs
from app.models.common import utcnow
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.repositories.relationships import RelationshipRepository
from app.repositories.users import UserRepository
from app.seed import reset_seed, seed_database
from app.services.progress import GLOBAL_CHANNEL, ProgressHub, hub
from tests.helpers import png_bytes


class FakeWS:
    def __init__(self, token: str | None, max_messages: int = 2) -> None:
        self.query_params = {"token": token} if token else {}
        self.sent: list[dict[str, Any]] = []
        self.closed: tuple[int, str] | None = None
        self.max = max_messages

    async def accept(self) -> None:
        return None

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)

    async def send_json(self, data: dict[str, Any]) -> None:
        self.sent.append(data)
        if len(self.sent) >= self.max:
            raise WebSocketDisconnect()


async def _admin_token(db) -> str:
    admin = await UserRepository(db).by_username("admin")
    return create_access_token(admin["_id"], "admin")


async def test_websocket_auth_and_snapshot_then_live_events(db, app):
    ws = FakeWS(None)
    await ws_routes.investigation_stream(ws, "inv_x")
    assert ws.closed[0] == 4401
    bad = FakeWS("garbage")
    await ws_routes.global_stream(bad)
    assert bad.closed[0] == 4401
    token = await _admin_token(db)
    missing = FakeWS(token)
    await ws_routes.investigation_stream(missing, "inv_missing")
    assert missing.closed[0] == 4404

    await db["investigations"].insert_one({"_id": "inv_ws", "status": "running", "created_at": utcnow()})
    live = FakeWS(token, max_messages=2)
    task = asyncio.create_task(ws_routes.investigation_stream(live, "inv_ws"))
    for _ in range(50):
        if hub.subscriber_count("inv_ws"):
            break
        await asyncio.sleep(0.02)
    await hub.publish("inv_ws", {"type": "stage_progress", "progress": 40, "timestamp": utcnow()})
    await asyncio.wait_for(task, 5)
    assert live.sent[0]["type"] == "snapshot" and live.sent[0]["investigation"]["id"] == "inv_ws"
    assert live.sent[1]["progress"] == 40
    assert hub.subscriber_count("inv_ws") == 0  # unsubscribed on disconnect

    events = FakeWS(token, max_messages=1)
    gtask = asyncio.create_task(ws_routes.global_stream(events))
    for _ in range(50):
        if hub.subscriber_count(GLOBAL_CHANNEL):
            break
        await asyncio.sleep(0.02)
    await hub.publish("inv_other", {"type": "investigation_status", "status": "completed"})
    await asyncio.wait_for(gtask, 5)
    assert events.sent[0]["status"] == "completed"


async def test_websocket_forbidden_role(db, make_user):
    # every built-in role may read investigations; a token for an unknown role is rejected at decode time
    user = await UserRepository(db).create("weird", "Password!123", "viewer")
    await db["users"].update_one({"_id": user["_id"]}, {"$set": {"disabled": True}})
    ws = FakeWS(create_access_token(user["_id"], "viewer"))
    await ws_routes.global_stream(ws)
    assert ws.closed[0] == 4401


async def test_progress_hub_drops_for_slow_subscribers():
    h = ProgressHub(queue_size=1)
    q = h.subscribe("c")
    await h.publish("c", {"n": 1})
    await h.publish("c", {"n": 2})  # dropped, queue full
    assert q.qsize() == 1 and (await q.get())["n"] == 1
    h.unsubscribe("c", q)
    assert h.subscriber_count() == 0


async def test_asset_routes_filters_detail_tags_and_files(client, admin_headers, db):
    repo = AssetRepository(db)
    a = await repo.upsert(
        "domain",
        "alpha.test",
        investigation_id="inv_a",
        source="dns",
        extra={"status": "ACTIVE", "confidence": 80, "cluster_ids": ["TIM-CL-X"]},
    )
    b = await repo.upsert("ip", "192.0.2.50", investigation_id="inv_a", source="dns", extra={"status": "UNKNOWN"})
    await repo.upsert("domain", "beta.test", source="crtsh", extra={"status": "PARKED", "confidence": 30})
    await RelationshipRepository(db).upsert(
        a["_id"], b["_id"], "RESOLVES_TO", investigation_id="inv_a", provider="dns", evidence={"record": "A"}
    )
    q = lambda params: client.get(f"/assets?{params}", headers=admin_headers)  # noqa: E731
    assert (await q("q=ALPHA")).json()["total"] == 1
    assert (await q("type=domain&type=ip")).json()["total"] == 3
    assert (await q("status=PARKED")).json()["items"][0]["value"] == "beta.test"
    assert (await q("min_confidence=50")).json()["total"] == 1
    assert (await q("cluster_id=TIM-CL-X")).json()["total"] == 1
    assert (await q("investigation_id=inv_a&sort=value&order=asc")).json()["items"][0]["value"] == "192.0.2.50"
    assert (await q("source=crtsh")).json()["total"] == 1
    detail = (await client.get(f"/asset/{a['_id']}", headers=admin_headers)).json()
    assert detail["asset"]["value"] == "alpha.test"
    assert detail["relationships"][0]["type"] == "RESOLVES_TO" and detail["relationships"][0]["direction"] == "out"
    assert (await client.get("/asset/nope", headers=admin_headers)).status_code == 404
    tagged = await client.put(
        f"/asset/{a['_id']}/tags", headers=admin_headers, json={"tags": ["Phish", " phish ", "x"]}
    )
    assert tagged.json()["tags"] == ["phish", "x"]
    assert (await client.put("/asset/nope/tags", headers=admin_headers, json={"tags": []})).status_code == 404

    arts = ArtifactRepository(db, get_fs())
    png = await arts.store_file(
        "screenshot_desktop", png_bytes(), filename="s.png", content_type="image/png", asset_id=a["_id"]
    )
    html = await arts.store_file(
        "html", b"<script>alert(1)</script>", filename="p.html", content_type="text/html", asset_id=a["_id"]
    )
    img = await client.get(f"/files/{png['file_id']}", headers=admin_headers)
    assert img.headers["content-type"] == "image/png" and "sandbox" in img.headers["content-security-policy"]
    hostile = await client.get(f"/files/{html['file_id']}", headers=admin_headers)
    assert hostile.headers["content-type"] == "application/octet-stream"  # never rendered inline
    assert "attachment" in hostile.headers["content-disposition"]
    assert len((await client.get(f"/asset/{a['_id']}", headers=admin_headers)).json()["artifacts"]) == 2
    assert await arts.delete_for_investigation("inv_none") == 0


async def test_investigation_endpoints_cancel_rerun_and_conflicts(client, admin_headers, app, monkeypatch, db):
    scheduled: list[str] = []
    monkeypatch.setattr(app.state.runner, "schedule", lambda inv_id: scheduled.append(inv_id))
    inv = (await client.post("/investigate", headers=admin_headers, json={"ioc": "rerun.test"})).json()
    assert (await client.post(f"/investigation/{inv['id']}/cancel", headers=admin_headers)).status_code == 409
    rerun = await client.post(f"/investigation/{inv['id']}/rerun", headers=admin_headers)
    assert rerun.status_code == 202 and rerun.json()["normalized"] == "rerun.test" and rerun.json()["id"] != inv["id"]
    assert len(scheduled) == 2
    listing = await client.get("/investigations?status=queued&tag=none", headers=admin_headers)
    assert listing.json()["total"] == 0
    assert (await client.post("/investigation/missing/rerun", headers=admin_headers)).status_code == 404


async def test_seed_dataset_counts_and_reset(db):
    counts = await seed_database(db, get_fs())
    assert counts == {"domains": 100, "ips": 30, "certificates": 15, "clusters": 10}
    assert await db["clusters"].count_documents({"tags": "demo"}) == 10
    assert await db["investigations"].count_documents({"seed": True, "status": "completed"}) == 10
    cluster = await db["clusters"].find_one({"tags": "demo"})
    assert cluster["counts"]["ip"] >= 1 and cluster["screenshots"] and cluster["confidence"] >= 50
    contoso = await db["investigations"].find_one({"normalized": "contoso-secure.test"})
    assert contoso["summary"]["clusters"] == 1 and contoso["summary"]["high_confidence"] >= 3
    root = await db["assets"].find_one({"value": "contoso-secure.test"})
    assert root["impersonation_score"] >= 50 and root["status"] == "ACTIVE"
    assert await seed_database(db, get_fs()) == {}  # idempotent
    removed = await reset_seed(db, get_fs())
    assert removed["investigations"] == 10 and await db["assets"].count_documents({"seed": True}) == 0


async def test_cli_user_helpers(db, capsys):
    assert await create_user_in(db, "cliuser", "Password!123", "viewer")
    assert not await create_user_in(db, "cliuser", "Password!123")
    assert await reset_password_in(db, "cliuser", "NewPassword!1")
    assert not await reset_password_in(db, "ghost", "x" * 10)
    assert cli_main(["--help"]) == 0
    assert cli_main(["bogus"]) == 2
    out = capsys.readouterr().out
    assert "Created viewer 'cliuser'" in out and "db-setup" in out


@pytest.mark.parametrize("ioc", ["192.0.2.1", "a" * 64])
async def test_dashboard_after_seed_style_activity(client, admin_headers, app, monkeypatch, ioc):
    monkeypatch.setattr(app.state.runner, "schedule", lambda inv_id: None)
    await client.post("/investigate", headers=admin_headers, json={"ioc": ioc})
    data = (await client.get("/dashboard", headers=admin_headers)).json()
    assert data["stats"]["investigations_today"] == 1 and data["stats"]["investigations_running"] == 1
