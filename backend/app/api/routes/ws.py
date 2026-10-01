"""WebSocket streams for real-time investigation progress."""

from __future__ import annotations

import asyncio
import contextlib

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder

from app.api.deps import user_from_token
from app.core.security import Permission, has_permission
from app.db.mongo import get_db
from app.repositories.investigations import InvestigationRepository
from app.services.progress import GLOBAL_CHANNEL, hub

router = APIRouter(tags=["Realtime"])
PING_SECONDS = 25


async def _authenticate(ws: WebSocket) -> bool:
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=4401, reason="missing token")
        return False
    try:
        user = await user_from_token(token)
    except HTTPException:
        await ws.close(code=4401, reason="invalid token")
        return False
    if not has_permission(user.role, Permission.INVESTIGATION_READ):
        await ws.close(code=4403, reason="forbidden")
        return False
    return True


async def _pump(ws: WebSocket, channel: str) -> None:
    queue = hub.subscribe(channel)
    try:
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=PING_SECONDS)
            except TimeoutError:
                await ws.send_json({"type": "ping"})
                continue
            await ws.send_json(message)
    finally:
        hub.unsubscribe(channel, queue)


@router.websocket("/ws/investigations/{inv_id}")
async def investigation_stream(ws: WebSocket, inv_id: str) -> None:
    """Sends a `snapshot` of the investigation, then live stage events. Auth: `?token=<JWT>`."""
    await ws.accept()
    if not await _authenticate(ws):
        return
    doc = await InvestigationRepository(get_db()).get(inv_id, {"provider_runs": 0})
    if doc is None:
        await ws.close(code=4404, reason="investigation not found")
        return
    doc["id"] = doc.pop("_id")
    await ws.send_json({"type": "snapshot", "investigation": jsonable_encoder(doc)})
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        await _pump(ws, inv_id)


@router.websocket("/ws/events")
async def global_stream(ws: WebSocket) -> None:
    """All investigation events (used by the dashboard). Auth: `?token=<JWT>`."""
    await ws.accept()
    if not await _authenticate(ws):
        return
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        await _pump(ws, GLOBAL_CHANNEL)
