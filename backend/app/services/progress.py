"""In-process pub/sub hub for real-time investigation progress (consumed by WebSockets)."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

from fastapi.encoders import jsonable_encoder

log = logging.getLogger(__name__)

GLOBAL_CHANNEL = "*"


class ProgressHub:
    def __init__(self, queue_size: int = 500) -> None:
        self._subs: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._queue_size = queue_size

    def subscribe(self, channel: str) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        self._subs[channel].add(q)
        return q

    def unsubscribe(self, channel: str, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._subs[channel].discard(q)
        if not self._subs[channel]:
            self._subs.pop(channel, None)

    def subscriber_count(self, channel: str | None = None) -> int:
        if channel:
            return len(self._subs.get(channel, ()))
        return sum(len(s) for s in self._subs.values())

    async def publish(self, channel: str, message: dict[str, Any]) -> None:
        payload = jsonable_encoder(message)
        for target in (channel, GLOBAL_CHANNEL):
            for q in list(self._subs.get(target, ())):
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    log.debug("Dropping progress message for slow subscriber on %s", target)


hub = ProgressHub()
