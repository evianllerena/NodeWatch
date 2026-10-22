"""A minimal synchronous ASGI client (no httpx needed).

Requests come from a loopback client address and carry the per-launch request token, exactly as the
NodeWatch page does. Use ``client(token=None)`` or ``client(host="10.0.0.5")`` to test refusals.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8") or "null")

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Client:
    def __init__(self, app, *, token: str | None = "auto", host: str = "127.0.0.1", headers: dict | None = None):
        self.app = app
        self.host = host
        self.extra = dict(headers or {})
        if token == "auto":
            from app.core.security import WRITE_REQUEST_TOKEN

            token = WRITE_REQUEST_TOKEN
        self.token = token

    def request(self, method: str, path: str, *, params: dict | None = None, json_body: Any = None,
                headers: dict | None = None, timeout: float = 30.0) -> Response:
        body = b"" if json_body is None else json.dumps(json_body).encode("utf-8")
        hdrs = {"host": "127.0.0.1:8765", **self.extra, **(headers or {})}
        if self.token:
            hdrs.setdefault("x-nodewatch-request", self.token)
        if body:
            hdrs.setdefault("content-type", "application/json")
            hdrs["content-length"] = str(len(body))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": urlencode(params or {}, doseq=True).encode(),
            "root_path": "",
            "headers": [(k.lower().encode(), str(v).encode()) for k, v in hdrs.items()],
            "client": (self.host, 50000) if self.host else None,
            "server": ("127.0.0.1", 8765),
        }
        return asyncio.run(asyncio.wait_for(self._call(scope, body), timeout))

    async def _call(self, scope, body: bytes) -> Response:
        sent = False
        out = Response(status=0)
        chunks: list[bytes] = []

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await asyncio.sleep(3600)
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                out.status = message["status"]
                out.headers = {k.decode().lower(): v.decode() for k, v in message.get("headers", [])}
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))

        await self.app(scope, receive, send)
        out.body = b"".join(chunks)
        return out

    def get(self, path: str, **kw) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> Response:
        return self.request("POST", path, **kw)


def api_routes(app) -> list[tuple[str, str, Any]]:
    """[(method, path, endpoint)] for every API route, including routers included by FastAPI."""
    from fastapi.routing import APIRoute

    found: list[tuple[str, str, Any]] = []

    def walk(routes):
        for r in routes:
            if isinstance(r, APIRoute):
                for m in sorted(r.methods or ()):
                    found.append((m, r.path, r.endpoint))
            elif getattr(r, "original_router", None) is not None:
                walk(r.original_router.routes)
            elif getattr(r, "routes", None) and not type(r).__name__ == "Mount":
                walk(r.routes)

    walk(app.router.routes)
    return sorted(set(found), key=lambda x: (x[1], x[0]))
