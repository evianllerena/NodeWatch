"""Keep-alive HTTPS client for Strata Logging Service log queries (v0.10.15).

``urllib``'s default opener opens a new TCP + TLS connection (and, behind a corporate
proxy, a new CONNECT tunnel) for every request and does not ask for compression.
Traffic & Sessions sends several Log Viewer queries per device and a live poll every
20 seconds, so that set-up cost was paid again and again, and multi-megabyte JSON
answers were downloaded uncompressed.

``KeepAliveOpener`` is a drop-in for the ``opener.open(request, timeout=...)`` interface
the provider already uses:

* connections are pooled per host (and proxy) and reused while the server keeps them open;
* ``Accept-Encoding: gzip`` is sent and gzip answers are decompressed;
* redirects are never followed (credentials must not be forwarded) - any non-2xx answer
  is raised as ``urllib.error.HTTPError`` exactly like the ``ApprovedSlsRedirectHandler``
  opener did, so error handling is unchanged;
* system proxy settings (``HTTPS_PROXY`` / Windows Internet Options) are honoured the same
  way urllib honours them, via ``urllib.request.getproxies``/``proxy_bypass``;
* TLS uses the default verified context. Verification is never disabled.

Each response carries ``timing`` (connect/first-byte/download milliseconds, bytes on the
wire and whether the connection was reused) for Traffic & Sessions diagnostics.
"""

from __future__ import annotations

import base64
import http.client
import io
import ssl
import threading
import time
import zlib
from email.message import Message
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, getproxies, proxy_bypass

_MAX_IDLE_PER_KEY = 16  # v0.10.40: covers a page's burst of parallel reads and the connectors' 8 workers
_CONNECT_TIMEOUT = 10.0  # TCP + TLS (+ proxy tunnel); a host that does not answer in 10 s is not coming
_DEADLINE_SLACK = 10.0  # the whole request (connect, wait, download) ends by timeout + this
_READ_CHUNK = 256 * 1024
_IDLE_SECONDS = 50.0  # most load balancers drop idle connections after 60 s


class PooledResponse(io.BytesIO):
    """Fully-read response body with the attributes urllib responses expose."""

    def __init__(self, body: bytes, status: int, reason: str, headers: Message, url: str, timing: dict[str, Any]):
        super().__init__(body)
        self.status = status
        self.code = status
        self.reason = reason
        self.headers = headers
        self.url = url
        self.timing = timing

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _decode(body: bytes, encoding: str, limit: int | None = None) -> bytes:
    """Decompress gzip/deflate. With ``limit`` the output stops at ``limit + 1`` bytes, so a
    compressed answer can never expand past what the caller accepts (v0.10.23)."""
    encoding = (encoding or "").strip().lower()
    if encoding not in ("gzip", "deflate"):
        return body
    cap = (limit + 1) if limit else 0
    if encoding == "gzip":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return d.decompress(body, cap) if cap else d.decompress(body) + d.flush()
    try:
        d = zlib.decompressobj()
        return d.decompress(body, cap) if cap else d.decompress(body) + d.flush()
    except zlib.error:
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        return d.decompress(body, cap) if cap else d.decompress(body) + d.flush()


class ResponseTooLarge(URLError):
    """The answer (after decompression) is bigger than the caller's ``max_bytes`` (v0.10.23)."""


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _read_until(resp, conn, deadline: float, max_bytes: int | None) -> bytes:
    """The response body, read in chunks so the request deadline also bounds the download."""
    chunks: list[bytes] = []
    total = 0
    cap = (max_bytes + 1) if max_bytes else None
    while True:
        left = deadline - time.perf_counter()
        if left <= 0:
            conn.close()
            raise TimeoutError("the answer did not finish downloading in time")
        if getattr(conn, "sock", None) is not None:
            try:
                conn.sock.settimeout(max(0.5, min(left, conn.sock.gettimeout() or left)))
            except OSError:
                pass
        want = _READ_CHUNK if cap is None else min(_READ_CHUNK, cap - total)
        if want <= 0:
            break
        part = resp.read1(want)  # what has arrived (one socket read), so the deadline is checked often
        if not part:
            break
        chunks.append(part)
        total += len(part)
    return b"".join(chunks)


class KeepAliveOpener:
    """``retry_unsafe``: retry a POST/PUT/DELETE once on a pooled connection the server closed.
    Only for read-only query APIs (Strata log queries, the default); shared openers that also carry
    writes (Mist, connectors) pass False so a change is never sent twice (v0.10.23)."""

    def __init__(
        self,
        *,
        context: ssl.SSLContext | None = None,
        proxies: dict[str, str] | None = None,
        retry_unsafe: bool = True,
    ) -> None:
        self._retry_unsafe = retry_unsafe
        self._context = context or ssl.create_default_context()
        self._proxies = proxies  # None = read the system settings on each request (they rarely change)
        self._lock = threading.Lock()
        self._idle: dict[tuple, list[tuple[http.client.HTTPConnection, float]]] = {}
        self.stats = {"connections_opened": 0, "connections_reused": 0, "requests": 0}

    # ------------------------------------------------------------------ pool

    def _proxy_for(self, scheme: str, host: str) -> str | None:
        proxies = self._proxies if self._proxies is not None else getproxies()
        proxy = proxies.get(scheme) or (proxies.get("https") if scheme == "https" else None)
        if not proxy:
            return None
        try:
            if self._proxies is None and proxy_bypass(host):
                return None
        except Exception:  # noqa: BLE001 - a broken bypass list must not stop queries
            pass
        return proxy

    def _new_connection(self, scheme: str, host: str, port: int, proxy: str | None, timeout: float):
        if proxy:
            parts = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
            proxy_host = parts.hostname or ""
            proxy_port = parts.port or (443 if parts.scheme == "https" else 8080)
            if scheme == "https":
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    proxy_host, proxy_port, timeout=timeout, context=self._context
                )
                tunnel_headers = {}
                if parts.username:
                    raw = f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()
                    tunnel_headers["Proxy-Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
                conn.set_tunnel(host, port, headers=tunnel_headers)
                return conn
            return http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
        if scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=timeout, context=self._context)
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _checkout(self, key: tuple) -> http.client.HTTPConnection | None:
        now = time.monotonic()
        with self._lock:
            idle = self._idle.get(key) or []
            while idle:
                conn, since = idle.pop()
                if now - since < _IDLE_SECONDS:
                    return conn
                conn.close()
        return None

    def _checkin(self, key: tuple, conn: http.client.HTTPConnection) -> None:
        with self._lock:
            idle = self._idle.setdefault(key, [])
            if len(idle) >= _MAX_IDLE_PER_KEY:
                conn.close()
                return
            idle.append((conn, time.monotonic()))

    def close(self) -> None:
        with self._lock:
            for idle in self._idle.values():
                for conn, _ in idle:
                    conn.close()
            self._idle.clear()

    # ------------------------------------------------------------------ open

    def open(self, req: Request, timeout: float | None = None, max_bytes: int | None = None) -> PooledResponse:
        url = req.full_url
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("https", "http") or not parts.hostname:
            raise URLError(f"unsupported URL scheme for log queries: {scheme}")
        host = parts.hostname
        port = parts.port or (443 if scheme == "https" else 80)
        proxy = self._proxy_for(scheme, host)
        key = (scheme, host, port, proxy)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if proxy and scheme == "http":
            path = url  # plain-HTTP proxies take the absolute URL
        headers = {k: v for k, v in req.header_items()}
        headers.setdefault("Accept-Encoding", "gzip")
        headers.setdefault("Connection", "keep-alive")
        headers["Host"] = host if parts.port in (None, 443, 80) else f"{host}:{port}"
        body = req.data
        method = req.get_method()
        timeout = float(timeout or 30)

        attempt = 0
        while True:
            attempt += 1
            conn = self._checkout(key)
            reused = conn is not None
            started = time.perf_counter()
            if conn is None:
                conn = self._new_connection(scheme, host, port, proxy, timeout)
            # v0.10.40: a wall-clock deadline for the whole request. The socket timeout alone applies to
            # each connect/read separately, so one call could take 2x the timeout (field: 40 s) or, with
            # a slowly trickling answer, much longer (field: 89 s).
            deadline = started + timeout + _DEADLINE_SLACK
            conn.timeout = min(timeout, _CONNECT_TIMEOUT) if not reused else timeout
            if getattr(conn, "sock", None) is not None:
                try:
                    conn.sock.settimeout(timeout)
                except OSError:
                    pass
            sent = False
            try:
                if not reused:
                    conn.connect()
                    if getattr(conn, "sock", None) is not None:
                        conn.sock.settimeout(timeout)
                connected = time.perf_counter()
                conn.request(method, path, body=body, headers=headers)
                sent = True
                resp = conn.getresponse()
                first_byte = time.perf_counter()
                raw = _read_until(resp, conn, deadline, max_bytes)
                if max_bytes and len(raw) > max_bytes:
                    conn.close()
                    raise ResponseTooLarge(f"the answer is larger than {max_bytes} bytes")
                done = time.perf_counter()
            except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError, http.client.BadStatusLine):
                conn.close()
                # A pooled connection the server already closed: retry once on a new one. A request
                # that was fully sent may have been processed, so only safe methods (or read-only
                # query APIs, retry_unsafe) are sent again (v0.10.23).
                if reused and attempt == 1 and (not sent or method.upper() in _SAFE_METHODS or self._retry_unsafe):
                    continue
                raise URLError("the log query host closed the connection") from None
            except ResponseTooLarge:
                raise
            except TimeoutError:
                conn.close()
                raise
            except (OSError, http.client.HTTPException) as exc:
                conn.close()
                raise URLError(exc) from exc
            break

        with self._lock:
            self.stats["requests"] += 1
            self.stats["connections_reused" if reused else "connections_opened"] += 1
        message = Message()
        for name, value in resp.getheaders():
            message[name] = value
        if resp.will_close or (max_bytes and not resp.isclosed()):
            conn.close()  # an unread remainder must not leak into the next request
        else:
            self._checkin(key, conn)
        try:
            payload = _decode(raw, message.get("Content-Encoding", ""), max_bytes)
        except (OSError, zlib.error, EOFError) as exc:
            raise URLError(f"could not decompress the response: {exc}") from exc
        timing = {
            "reused_connection": reused,
            "connect_ms": int((connected - started) * 1000),
            "wait_ms": int((first_byte - connected) * 1000),
            "download_ms": int((done - first_byte) * 1000),
            "wire_bytes": len(raw),
            "bytes": len(payload),
            "compressed": len(raw) != len(payload),
        }
        if not 200 <= resp.status < 300:
            raise HTTPError(url, resp.status, resp.reason, message, io.BytesIO(payload))
        return PooledResponse(payload, resp.status, resp.reason, message, url, timing)
