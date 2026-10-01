"""Lightweight in-process request metrics exposed in Prometheus text format."""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

STARTED_AT = time.time()


class Metrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self.requests: dict[tuple[str, str, int], int] = defaultdict(int)
        self.latency_sum: dict[tuple[str, str], float] = defaultdict(float)
        self.latency_count: dict[tuple[str, str], int] = defaultdict(int)

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        with self._lock:
            self.requests[(method, route, status)] += 1
            self.latency_sum[(method, route)] += seconds
            self.latency_count[(method, route)] += 1

    def snapshot(self) -> dict[str, dict[Any, Any]]:
        with self._lock:
            return {
                "requests": dict(self.requests),
                "latency_sum": dict(self.latency_sum),
                "latency_count": dict(self.latency_count),
            }


metrics = Metrics()


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            path = getattr(route, "path", None) or "unmatched"
            metrics.observe(request.method, path, status, time.perf_counter() - start)


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_prometheus(gauges: dict[str, float]) -> str:
    snap = metrics.snapshot()
    lines = [
        "# HELP tim_uptime_seconds Process uptime in seconds",
        "# TYPE tim_uptime_seconds gauge",
        f"tim_uptime_seconds {time.time() - STARTED_AT:.0f}",
        "# HELP tim_http_requests_total HTTP requests by method, route and status",
        "# TYPE tim_http_requests_total counter",
    ]
    for (method, route, status), n in sorted(snap["requests"].items()):
        lines.append(f'tim_http_requests_total{{method="{method}",route="{_esc(route)}",status="{status}"}} {n}')
    lines += [
        "# HELP tim_http_request_duration_seconds Request latency",
        "# TYPE tim_http_request_duration_seconds summary",
    ]
    for (method, route), total in sorted(snap["latency_sum"].items()):
        count = snap["latency_count"][(method, route)]
        labels = f'method="{method}",route="{_esc(route)}"'
        lines.append(f"tim_http_request_duration_seconds_sum{{{labels}}} {total:.6f}")
        lines.append(f"tim_http_request_duration_seconds_count{{{labels}}} {count}")
    for name, value in sorted(gauges.items()):
        lines += [f"# TYPE tim_{name} gauge", f"tim_{name} {value}"]
    return "\n".join(lines) + "\n"
