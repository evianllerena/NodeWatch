from __future__ import annotations

from app.core.version import APP_VERSION

import email.utils
import hashlib
import http.client
import json
import math
import re
import socket
import ssl
import threading
import time
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import Request

from app.core.config import DIAGNOSTICS_ROOT, STATE_ROOT, Settings, get_settings
from app.core.freshness import in_context, no_stale, stale_allowed
from app.core.file_utils import append_jsonl_rotating_async, write_private_text
from app.core.security import redact_text
from app.services.mist_event_buffer import RollingEventBuffer


class MistApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class CacheEntry:
    expires_at: float
    value: Any
    ttl: float = 0.0  # the lifetime it was stored with (sets how long it may be served stale while refreshing)


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_MAC = re.compile(r"^[0-9a-fA-F]{12}$")
_PAGE_LIMIT = 1000  # Mist's maximum page size
_MAX_PAGES = 100  # hard stop for one logical read
_MAX_ITEMS = 100_000
_CACHE_MAX_ENTRIES = 512

# ---------------------------------------------------------------- API budget (v0.10.18)
# Mist allows 5,000 API calls per hour per token, shared with everything else the customer runs.
MIST_HOURLY_LIMIT = 5000
USAGE_HIGH = 0.70  # above this share of the hourly limit, cache lifetimes double
USAGE_CRITICAL = 0.90  # above this, they quadruple
_RETRY_AFTER_DEFAULT = 60.0
_RETRY_AFTER_MAX = 3600.0
# How long one logical read stays fresh, by endpoint (seconds, before the budget multiplier). Reads not
# listed use Settings.cache_seconds. The user's Refresh button clears everything (MistClient.clear_cache).
_TTL_RULES: tuple[tuple[re.Pattern, float], ...] = (
    (re.compile(r"^/api/v1/orgs/[^/]+$"), 600.0),  # organisation object (status check)
    (re.compile(r"/orgs/[^/]+/sites$"), 600.0),  # site list: changes rarely
    (re.compile(r"/orgs/[^/]+/inventory$"), 300.0),  # claimed devices / VC membership
    (re.compile(r"/orgs/[^/]+/inventory/search$"), 120.0),  # also the "device connected?" source
    (re.compile(r"/stats/sites$"), 60.0),
    # Mist refreshes device/port statistics about once a minute; reading them faster only costs budget.
    (re.compile(r"/stats/devices$"), 60.0),
    (re.compile(r"/stats/devices/[^/]+$"), 30.0),
    (re.compile(r"/stats/ports/search$"), 60.0),
    (re.compile(r"/alarms/search$"), 60.0),
    (re.compile(r"/logs/search$"), 120.0),
    (re.compile(r"^/api/v1/const/"), 3600.0),
    (re.compile(r"/orgs/[^/]+/(admins|apitokens)$"), 600.0),  # who-is-who for the Activity Log (v0.10.24)
)
# Stale-while-revalidate (v0.10.40): a read whose cached answer has just expired is answered at once with
# that answer while one background read refreshes it, instead of making the page wait for Mist (stats/devices
# takes ~5 s). Only for a short grace after expiry (4x the lifetime, 4-15 min); older answers, answers
# dropped by Refresh or a write, and fresh=True reads always wait for Mist.
_SWR_FACTOR = 4.0
_SWR_MIN = 240.0
_SWR_MAX = 900.0
_SWR_WORKERS = 4
_EVENT_POLL_SECONDS = 30.0  # device events: incremental read at most this often per consumer read
_EVENT_FRESH_MAX_AGE = 10.0  # fresh=True event reads (alerting monitor) accept events this old
_EVENT_BUFFER_MAX = 50_000
_EVENT_QUICK_SECONDS = 3600.0  # first event read covers the last hour; the rest is back-filled
_ORG_EVENTS_SUFFIX = "/devices/events/search"


def endpoint_template(path: str) -> str:
    """``/api/v1/orgs/<uuid>/sites`` → ``/api/v1/orgs/{id}/sites`` (no IDs or MACs in counters)."""
    path = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}", path)
    return re.sub(r"/[0-9a-fA-F]{12}(?=/|$)", "/{mac}", path)


def duration_seconds(text: Any) -> float | None:
    """Mist duration (``30m``, ``12h``, ``1d``, ``2w``) in seconds; None when not understood."""
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", str(text or ""))
    if not m:
        return None
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]


def _retry_after_seconds(value: Any, now: float) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, when.timestamp() - now)


class _ApiUsage:
    """Real Mist calls in the last hour for one API token (shared by every client using it)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls: deque[tuple[float, str]] = deque()
        self.cache_hits: deque[float] = deque()
        self.backoff_until = 0.0
        self.rate_limited = 0  # consecutive HTTP 429 answers
        self.last_429 = 0.0
        self.level = "ok"

    def _trim(self, now: float) -> None:
        cutoff = now - 3600.0
        while self.calls and self.calls[0][0] < cutoff:
            self.calls.popleft()
        while self.cache_hits and self.cache_hits[0] < cutoff:
            self.cache_hits.popleft()

    def note_call(self, endpoint: str, now: float) -> None:
        with self.lock:
            self.calls.append((now, endpoint))
            self._trim(now)

    def note_hit(self, now: float) -> None:
        with self.lock:
            self.cache_hits.append(now)
            self._trim(now)

    def count(self, now: float) -> int:
        with self.lock:
            self._trim(now)
            return len(self.calls)


_USAGE: dict[str, _ApiUsage] = {}
_USAGE_LOCK = threading.Lock()


def _usage_for(token: str) -> _ApiUsage:
    key = hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:16]  # never the token itself
    with _USAGE_LOCK:
        usage = _USAGE.get(key)
        if usage is None:
            usage = _USAGE[key] = _ApiUsage()
        return usage


def reset_api_usage() -> None:
    """Forget call counters and back-off state (tests)."""
    with _USAGE_LOCK:
        _USAGE.clear()


# One pooled keep-alive HTTPS opener per TLS mode, shared by every MistClient (v0.10.23). urlopen opened
# a new TCP + TLS connection (and a fresh DNS lookup) for every call; field diagnostics showed 16 % of
# Mist calls stalling ~12 s in name resolution and every call paying a TLS handshake.
_OPENERS: dict[bool, Any] = {}
_OPENERS_LOCK = threading.Lock()


def _shared_opener(verify_tls: bool, context: ssl.SSLContext):
    # Imported lazily: app.integrations imports this module through its Mist provider.
    from app.integrations.providers.sls_http import KeepAliveOpener

    with _OPENERS_LOCK:
        opener = _OPENERS.get(bool(verify_tls))
        if opener is None:
            opener = _OPENERS[bool(verify_tls)] = KeepAliveOpener(context=context, retry_unsafe=False)  # Mist writes are never sent twice
        return opener


def reset_connection_pool() -> None:
    """Close pooled Mist connections (settings changed: host, TLS mode or proxy)."""
    with _OPENERS_LOCK:
        openers = list(_OPENERS.values())
        _OPENERS.clear()
    for opener in openers:
        try:
            opener.close()
        except Exception:  # noqa: BLE001
            pass


_REVALIDATE_POOL: ThreadPoolExecutor | None = None
_REVALIDATE_LOCK = threading.Lock()


def _revalidate_pool() -> ThreadPoolExecutor:
    global _REVALIDATE_POOL
    with _REVALIDATE_LOCK:
        if _REVALIDATE_POOL is None:
            _REVALIDATE_POOL = ThreadPoolExecutor(max_workers=_SWR_WORKERS, thread_name_prefix="mist-refresh")
        return _REVALIDATE_POOL


class _Flight:
    __slots__ = ("done", "value", "error")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.value: Any = None
        self.error: BaseException | None = None


def _path_id(value: Any, name: str) -> str:
    """Validate a Mist object ID (UUID) before it is placed in a URL path."""
    text = str(value or "").strip()
    if not _UUID.match(text):
        raise MistApiError(f"Invalid Mist {name}: expected a UUID", 400)
    return text.lower()


def _path_mac(value: Any, name: str = "MAC address") -> str:
    text = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if not _MAC.match(text):
        raise MistApiError(f"Invalid {name}", 400)
    return text.lower()


class MistClient:
    """Shared Mist REST client for monitoring and guarded operational actions."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        # Bounded LRU: keys include per-query MACs/text, so an unbounded dict grows forever.
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._timing_log = DIAGNOSTICS_ROOT / "api_timing.jsonl"
        # Single flight: concurrent identical reads share one Mist round trip.
        self._flights: dict[str, _Flight] = {}
        self._flight_lock = threading.Lock()
        self._revalidating: set[str] = set()
        self._generation = 0  # bumped whenever cached reads are dropped (Refresh, writes)
        self._event_buffer: RollingEventBuffer | None = None
        self._event_buffer_lock = threading.Lock()

    @property
    def _org(self) -> str:
        # Report "not configured" (409) before complaining about the ID format.
        if not self.configured:
            raise MistApiError("Mist connection is not configured", 409)
        return _path_id(self.settings.org_id, "organization ID")

    def _cache_get(self, key: str, now: float, *, allow_stale: bool = False) -> CacheEntry | None:
        # Expired entries stay (the LRU bounds them) so a rate-limited client can serve the last answer.
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now and not allow_stale:
                return None
            self._cache.move_to_end(key)
            return entry

    @staticmethod
    def no_stale():
        """Reads inside wait for Mist when their cached answer expired (alerting decides on current data)."""
        return no_stale()

    def _cache_get_swr(self, key: str, now: float) -> tuple[CacheEntry | None, bool]:
        """(entry, stale): a fresh entry, or one that expired within its grace (stale=True: the caller serves
        it and refreshes in the background), or (None, False)."""
        if not stale_allowed():
            return self._cache_get(key, now), False
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None, False
            if entry.expires_at > now:
                self._cache.move_to_end(key)
                return entry, False
            if entry.expires_at <= 0 or not entry.ttl:  # dropped by Refresh/a write during a back-off
                return None, False
            grace = min(_SWR_MAX, max(_SWR_MIN, entry.ttl * _SWR_FACTOR))
            if now - entry.expires_at > grace:
                return None, False
            self._cache.move_to_end(key)
            return entry, True

    def _revalidate(self, key: str, load) -> None:
        """Refresh one expired read in the background (once per key: the single flight dedupes)."""
        if self._backoff_remaining() > 0:
            return  # rate-limited: the stale answer is the best there is
        with self._flight_lock:
            if key in self._flights or key in self._revalidating:
                return
            self._revalidating.add(key)

        def run() -> None:
            try:
                self._shared(key, load)
            except Exception:  # noqa: BLE001 - the next read retries in the foreground
                pass
            finally:
                with self._flight_lock:
                    self._revalidating.discard(key)

        try:
            _revalidate_pool().submit(run)
        except RuntimeError:  # interpreter shutting down
            with self._flight_lock:
                self._revalidating.discard(key)

    def _cache_put(self, key: str, entry: CacheEntry, generation: int | None = None) -> None:
        """``generation``: the cache generation when the read started; a read that started before a
        Refresh or a write cleared the cache is not stored (it may hold the data from before the change)."""
        with self._cache_lock:
            if generation is not None and generation != self._generation:
                return
            self._cache[key] = entry
            self._cache.move_to_end(key)
            while len(self._cache) > _CACHE_MAX_ENTRIES:
                self._cache.popitem(last=False)

    # ------------------------------------------------------------ API budget

    @property
    def _usage(self) -> _ApiUsage:
        return _usage_for(self.settings.token)

    def _ttl_multiplier(self) -> float:
        """1× normally; 2× above 70 % and 4× above 90 % of Mist's hourly limit."""
        share = self._usage.count(time.time()) / MIST_HOURLY_LIMIT
        if share >= USAGE_CRITICAL:
            return 4.0
        if share >= USAGE_HIGH:
            return 2.0
        return 1.0

    def _ttl_for(self, path: str) -> float:
        base = float(self.settings.cache_seconds)
        for pattern, seconds in _TTL_RULES:
            if pattern.search(path):
                base = max(base, seconds)
                break
        return base * self._ttl_multiplier()

    def _note_call(self, path: str) -> None:
        usage = self._usage
        now = time.time()
        usage.note_call(endpoint_template(path), now)
        share = usage.count(now) / MIST_HOURLY_LIMIT
        level = "critical" if share >= USAGE_CRITICAL else "high" if share >= USAGE_HIGH else "ok"
        if level != usage.level:
            usage.level = level
            self._record_timing(
                method="BUDGET",
                path="(all)",
                duration_ms=0,
                status_code=None,
                ok=level == "ok",
                error=None if level == "ok" else self._usage_warning(int(share * MIST_HOURLY_LIMIT)),
            )

    @staticmethod
    def _usage_warning(calls: int) -> str:
        return (
            f"Mist API usage high: {calls:,} calls in the last hour (limit {MIST_HOURLY_LIMIT:,} per token); "
            "NodeWatch is caching longer to stay under it"
        )

    def _note_rate_limited(self, headers: dict[str, str]) -> float:
        usage = self._usage
        now = time.time()
        with usage.lock:
            usage.rate_limited += 1
            usage.last_429 = now
            wait = _retry_after_seconds(headers.get("retry-after"), now)
            if wait is None:  # no Retry-After: back off exponentially (60 s, 120 s, … capped)
                wait = _RETRY_AFTER_DEFAULT * (2 ** min(usage.rate_limited - 1, 6))
            wait = max(1.0, min(_RETRY_AFTER_MAX, wait))
            usage.backoff_until = max(usage.backoff_until, now + wait)
            return usage.backoff_until - now

    def _backoff_remaining(self) -> float:
        return max(0.0, self._usage.backoff_until - time.time())

    def api_usage(self) -> dict[str, Any]:
        """Calls in the last hour for this token, per endpoint, plus budget state (no secrets)."""
        usage = self._usage
        now = time.time()
        with usage.lock:
            usage._trim(now)
            per_endpoint = Counter(endpoint for _, endpoint in usage.calls)
            calls = len(usage.calls)
            hits = len(usage.cache_hits)
            last_429 = usage.last_429
        share = calls / MIST_HOURLY_LIMIT
        level = "critical" if share >= USAGE_CRITICAL else "high" if share >= USAGE_HIGH else "ok"
        backoff = self._backoff_remaining()
        warning = self._usage_warning(calls) if level != "ok" else ""
        if backoff:
            warning = (warning + "; " if warning else "") + (
                f"Mist answered HTTP 429 (rate limited): NodeWatch pauses Mist reads for {int(backoff)} s "
                "and shows the last data it has"
            )
        buffer = self._event_buffer
        return {
            "calls_last_hour": calls,
            "cache_hits_last_hour": hits,
            "hourly_limit": MIST_HOURLY_LIMIT,
            "percent_of_limit": round(share * 100, 1),
            "level": level,
            "ttl_multiplier": self._ttl_multiplier(),
            "warning": warning,
            "rate_limited_backoff_seconds": int(backoff),
            "last_rate_limited": datetime.fromtimestamp(last_429, timezone.utc).isoformat() if last_429 else None,
            "by_endpoint": dict(per_endpoint.most_common(20)),
            "device_event_buffer": buffer.stats() if buffer else None,
        }

    def _shared(self, key: str, fn) -> Any:
        """Run ``fn`` once for concurrent callers with the same ``key``; all get its result or error."""
        with self._flight_lock:
            flight = self._flights.get(key)
            leader = flight is None
            if leader:
                flight = self._flights[key] = _Flight()
        if not leader:
            flight.done.wait()
            if flight.error is not None:
                raise flight.error
            return flight.value
        try:
            flight.value = fn()
            return flight.value
        except BaseException as exc:
            flight.error = exc
            raise
        finally:
            with self._flight_lock:
                self._flights.pop(key, None)
            flight.done.set()

    def _record_timing(
        self,
        *,
        method: str,
        path: str,
        duration_ms: int,
        status_code: int | None,
        ok: bool,
        cache_hit: bool = False,
        error: str | None = None,
    ) -> None:
        """Append sanitized API timing data. Never records tokens, bodies, or query values."""
        if not cache_hit and duration_ms:
            from app.integrations import api_timing

            api_timing.note("mist", method, path, duration_ms, ok)
        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": method,
                "path": path,
                "duration_ms": duration_ms,
                "status_code": status_code,
                "ok": ok,
                "cache_hit": cache_hit,
            }
            if error:
                record["error"] = redact_text(error, self.settings.token)[:500]
            append_jsonl_rotating_async(self._timing_log, record)  # written off the request thread
        except Exception:
            # Diagnostics must never break the application.
            pass

    @property
    def configured(self) -> bool:
        return self.settings.configured and not self.settings.validate()

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self.settings.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"NodeWatch/{APP_VERSION}",
        }

    def _context(self):
        # Building a context loads the CA bundle (~30 ms); reuse one per client.
        context = getattr(self, "_ssl_context", None)
        if context is None:
            if self.settings.verify_tls:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()  # noqa: SLF001
            self._ssl_context = context
        return context

    @staticmethod
    def _extract(payload: Any) -> Any:
        if isinstance(payload, dict):
            for key in ("results", "data", "items"):
                if isinstance(payload.get(key), list):
                    return payload[key]
        return payload

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any | None = None,
        *,
        cache: bool = False,
        invalidate_all_cache: bool = True,
        allowed_statuses: tuple[int, ...] = (),
    ) -> Any:
        payload, _ = self._request_with_headers(
            method,
            path,
            params,
            body,
            cache=cache,
            invalidate_all_cache=invalidate_all_cache,
            allowed_statuses=allowed_statuses,
        )
        return payload

    def _request_with_headers(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any | None = None,
        *,
        cache: bool = False,
        invalidate_all_cache: bool = True,
        allowed_statuses: tuple[int, ...] = (),
    ) -> tuple[Any, dict[str, str]]:
        if not self.configured:
            raise MistApiError("Mist connection is not configured", 409)
        query = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        url = f"{self.settings.api_host}{path}"
        if query:
            url += "?" + urlencode(query)
        if not (method == "GET" and cache):
            payload, headers = self._send(method, path, url, body, allowed_statuses)
            if method != "GET" and invalidate_all_cache:
                self.clear_cache()
            return payload, headers

        cache_key = f"{method}:{url}"

        def load() -> tuple[Any, dict[str, str]]:
            again = self._cache_get(cache_key, time.time())  # filled while we waited for the flight
            if again is not None:
                return again.value
            gen = self._generation
            result = self._send(method, path, url, body, allowed_statuses)
            ttl = self._ttl_for(path)
            self._cache_put(cache_key, CacheEntry(time.time() + ttl, result, ttl), gen)
            return result

        hit, stale = self._cache_get_swr(cache_key, time.time())
        if hit is not None:
            self._note_hit(path)
            if stale:
                self._revalidate(cache_key, load)
            return hit.value  # (payload, headers)

        try:
            return self._shared(cache_key, load)
        except MistApiError as exc:
            stale = self._stale_for(exc, cache_key)
            if stale is None:
                raise
            return stale.value

    def _note_hit(self, path: str) -> None:
        # Counted only (api_usage reports hits per hour). A diagnostics line per hit cost a locked file
        # append on every cached read - thousands per hour - and told support nothing the counter does not.
        self._usage.note_hit(time.time())

    def _stale_for(self, exc: MistApiError, key: str) -> CacheEntry | None:
        """While Mist rate-limits us, the last answer (even expired) beats an error page."""
        if exc.status_code != 429:
            return None
        return self._cache_get(key, time.time(), allow_stale=True)

    def _send(
        self, method: str, path: str, url: str, body: Any | None, allowed_statuses: tuple[int, ...]
    ) -> tuple[Any, dict[str, str]]:
        """One real HTTP round trip to Mist, retried once for a read when name resolution failed.

        Field diagnostics (v0.10.23): on a cold start Windows name resolution failed after ~12 s for the
        first parallel reads and answered at once afterwards, so one immediate retry turns those errors
        into answers instead of empty dashboard sections. Writes are never retried."""
        try:
            return self._send_once(method, path, url, body, allowed_statuses)
        except MistApiError as exc:
            cause = exc.__cause__
            dns_failed = isinstance(cause, URLError) and isinstance(getattr(cause, "reason", None), socket.gaierror)
            # v0.10.40: a read is also retried once after a gateway error (502/503/504: a Mist front end
            # restarting or overloaded answers the next request) or a connection that could not be made.
            gateway = exc.status_code in (502, 503, 504)
            no_connect = isinstance(cause, (ConnectionRefusedError, ConnectionResetError)) or (
                isinstance(cause, URLError) and isinstance(getattr(cause, "reason", None), (ConnectionRefusedError, ConnectionResetError))
            )
            if method != "GET" or not (dns_failed or gateway or no_connect):
                raise
            if gateway:
                time.sleep(0.5)
        return self._send_once(method, path, url, body, allowed_statuses)

    def _send_once(
        self, method: str, path: str, url: str, body: Any | None, allowed_statuses: tuple[int, ...]
    ) -> tuple[Any, dict[str, str]]:
        """One real HTTP round trip to Mist (counted against the hourly budget)."""
        backoff = self._backoff_remaining()
        if backoff and method == "GET":
            # Reads wait out a 429 instead of extending it; user-confirmed writes still go through.
            self._record_timing(
                method=method, path=path, duration_ms=0, status_code=429, ok=False, error="skipped: rate-limit back-off"
            )
            raise MistApiError(
                f"Mist API rate limit reached (HTTP 429); NodeWatch retries in {int(math.ceil(backoff))} s", 429
            )
        started = time.perf_counter()
        payload_bytes = None if body is None else json.dumps(body).encode("utf-8")
        req = Request(url, headers=self.headers, data=payload_bytes, method=method)
        status_code: int | None = None
        headers: dict[str, str] = {}
        self._note_call(path)

        def fail(message: str, error: str, status: int | None = None, exc: BaseException | None = None):
            duration = int((time.perf_counter() - started) * 1000)
            self._record_timing(
                method=method, path=path, duration_ms=duration, status_code=status, ok=False, error=error
            )
            raise MistApiError(message, status) from exc

        try:
            opener = _shared_opener(self.settings.verify_tls, self._context())
            with opener.open(req, timeout=self.settings.request_timeout) as resp:
                status_code = getattr(resp, "status", None) or resp.getcode()
                headers = {k.lower(): v for k, v in (resp.headers.items() if resp.headers else [])}
                raw = resp.read().decode("utf-8")
                payload = json.loads(raw) if raw else None
        except HTTPError as exc:
            if exc.code in allowed_statuses:
                duration_ms = int((time.perf_counter() - started) * 1000)
                self._record_timing(method=method, path=path, duration_ms=duration_ms, status_code=exc.code, ok=True)
                return None, {}
            if exc.code == 429:
                err_headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
                wait = self._note_rate_limited(err_headers)
                fail(
                    f"Mist API rate limit reached (HTTP 429); NodeWatch retries in {int(math.ceil(wait))} s",
                    f"HTTP 429, backing off {int(wait)} s",
                    429,
                    exc,
                )
            try:
                raw = exc.read().decode("utf-8")
                detail = json.loads(raw) if raw else {}
                if isinstance(detail, dict):
                    message = detail.get("detail") or detail.get("message") or detail.get("error") or raw
                else:
                    message = raw
            except Exception:
                message = str(exc)
            fail(f"Mist API HTTP {exc.code}: {message}", str(message), exc.code, exc)
        except URLError as exc:
            fail(f"Unable to reach Mist API: {exc.reason}", str(exc.reason), None, exc)
        except json.JSONDecodeError as exc:
            fail("Mist API returned invalid JSON", "invalid JSON", status_code, exc)
        except (TimeoutError, ConnectionError, http.client.HTTPException, ssl.SSLError, OSError) as exc:
            # Read timeouts, resets and dropped connections are not URLError; without
            # this they escaped as non-Mist errors and turned whole pages into HTTP 500s.
            kind = "timed out" if isinstance(exc, TimeoutError) else type(exc).__name__
            fail(f"Mist API request failed ({kind}): {exc}", f"{kind}: {exc}", None, exc)

        duration_ms = int((time.perf_counter() - started) * 1000)
        self._record_timing(method=method, path=path, duration_ms=duration_ms, status_code=status_code, ok=True)
        usage = self._usage
        if usage.rate_limited:
            with usage.lock:
                usage.rate_limited = 0
        return payload, headers

    def _read_key(self, path: str, key_params: dict[str, Any], extra: str) -> str:
        query = {k: v for k, v in key_params.items() if v is not None and v != ""}
        return f"READ:{self.settings.api_host}{path}?{urlencode(sorted(query.items()))}#{extra}"

    def _cached_read(self, path: str, key_params: dict[str, Any], extra: str, fresh: bool, fn) -> list[dict]:
        """One logical (multi-page) read, cached as a whole for the endpoint's TTL and shared in flight."""
        key = self._read_key(path, key_params, extra)
        if fresh:
            return list(self._shared(key + "#fresh", fn))

        def load() -> list[dict]:
            again = self._cache_get(key, time.time())
            if again is not None:
                return again.value
            gen = self._generation
            rows = fn()
            ttl = self._ttl_for(path)
            self._cache_put(key, CacheEntry(time.time() + ttl, rows, ttl), gen)
            return rows

        hit, stale = self._cache_get_swr(key, time.time())
        if hit is not None:
            self._note_hit(path)
            if stale:
                self._revalidate(key, load)
            return list(hit.value)

        try:
            return list(self._shared(key, load))
        except MistApiError as exc:
            stale = self._stale_for(exc, key)
            if stale is None:
                raise
            return list(stale.value)

    # ---------------------------------------------------------------- paging

    def _get_paged(
        self, path: str, params: dict[str, Any] | None = None, *, max_items: int = _MAX_ITEMS, fresh: bool = False
    ) -> list[dict]:
        """Read every page of a Mist list endpoint (page/limit with X-Page-Total).

        The whole read is cached for the endpoint's TTL and shared by concurrent callers."""
        base = dict(params or {})
        return self._cached_read(
            path, base, f"paged:{max_items}", fresh, lambda: self._read_pages(path, base, max_items)
        )

    def _read_pages(self, path: str, base: dict[str, Any], max_items: int) -> list[dict]:
        rows: list[dict] = []
        for page in range(1, _MAX_PAGES + 1):
            payload, headers = self._request_with_headers("GET", path, {**base, "limit": _PAGE_LIMIT, "page": page})
            data = self._extract(payload)
            batch = [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
            rows.extend(batch)
            try:
                total = int(headers.get("x-page-total") or 0)
            except ValueError:
                total = 0
            if len(batch) < _PAGE_LIMIT or (total and len(rows) >= total) or len(rows) >= max_items:
                return rows[:max_items]
        self._record_timing(
            method="GET",
            path=path,
            duration_ms=0,
            status_code=None,
            ok=True,
            error=f"pagination stopped at {_MAX_PAGES} pages ({len(rows)} items)",
        )
        return rows[:max_items]

    def _search(
        self, path: str, params: dict[str, Any] | None = None, *, limit: int = _PAGE_LIMIT, fresh: bool = False
    ) -> list[dict]:
        """Read a Mist /search endpoint, following ``next`` until ``limit`` results.

        The whole read (all pages) is cached for the endpoint's TTL and shared by concurrent callers;
        ``next`` cursors change on every read, so caching single pages never helped page 2+."""
        wanted = max(1, min(int(limit), _MAX_ITEMS))
        base = dict(params or {})
        return self._cached_read(path, base, f"search:{wanted}", fresh, lambda: self._read_search(path, base, wanted))

    def _read_search(self, path: str, params: dict[str, Any], wanted: int) -> list[dict]:
        rows: list[dict] = []
        query = {**params, "limit": min(wanted, _PAGE_LIMIT)}
        current_path = path
        for _ in range(_MAX_PAGES):
            payload = self._request("GET", current_path, query)
            data = self._extract(payload)
            batch = [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
            rows.extend(batch)
            nxt = payload.get("next") if isinstance(payload, dict) else None
            if len(rows) >= wanted or not batch or not nxt:
                break
            parts = urlsplit(str(nxt))
            # Only follow same-host relative links to the same endpoint.
            if parts.scheme or parts.netloc or parts.path != path:
                break
            current_path = parts.path
            query = dict(parse_qsl(parts.query, keep_blank_values=False))
        return rows[:wanted]

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        cache: bool = True,
        allowed_statuses: tuple[int, ...] = (),
    ) -> Any:
        return self._request("GET", path, params=params, cache=cache, allowed_statuses=allowed_statuses)

    def post(self, path: str, body: Any | None = None) -> Any:
        return self._request("POST", path, body=body)

    def put(self, path: str, body: Any | None = None) -> Any:
        return self._request("PUT", path, body=body)

    def _forget(self, key: str) -> None:
        """Drop a cache entry (caller holds _cache_lock). During a 429 back-off it is only marked expired:
        the back-off serves expired entries as the last known answer, so a write must not wipe them."""
        entry = self._cache.get(key)
        if entry is None:
            return
        if self.__dict__.get("settings") is not None and self._backoff_remaining() > 0:
            entry.expires_at = 0.0
        else:
            self._cache.pop(key, None)

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._generation += 1
            for key in list(self._cache):
                self._forget(key)
            self.__dict__.pop("_lookup_cache", None)
        buffer = self.__dict__.get("_event_buffer")
        if buffer is not None:
            buffer.invalidate()  # next event read fetches what is new (incremental, not a full reload)

    # ------------------------------------------------------- name lookups

    _LOOKUP_TTL = 300.0

    def _cached_lookup(self, name: str, build) -> Any:
        """Small TTL cache for id→name maps used to label events (never raises)."""
        cache = self.__dict__.setdefault("_lookup_cache", {})
        now = time.monotonic()
        hit = cache.get(name)
        if hit and hit[0] > now:
            return hit[1]
        try:
            value = build() if self.configured else None
        except Exception:
            value = None
        if value is None:
            # Keep a stale map on failure rather than flapping back to UUIDs.
            return hit[1] if hit else {}
        cache[name] = (now + self._LOOKUP_TTL, value)
        return value

    def site_name_map(self) -> dict[str, str]:
        """site_id → site name for the configured org (cached; {} when unavailable)."""

        def build() -> dict[str, str]:
            return {
                str(s.get("id")): str(s.get("name") or "")
                for s in self.list_sites()
                if isinstance(s, dict) and s.get("id") and s.get("name")
            }

        return self._cached_lookup("sites", build)

    def device_directory(self) -> dict[str, dict]:
        """Device lookup keyed by device id and by bare lowercase MAC (cached).

        Each value is ``{"id", "mac", "name", "type", "site_id"}``; {} when unavailable.
        """

        def build() -> dict[str, dict]:
            out: dict[str, dict] = {}
            rows: list = []
            # Mist's inventory API rejects type=all ("valid types are: ap, ble, gateway, …"): one call per type.
            def read(dtype: str) -> list:
                try:
                    return self.list_org_inventory(device_type=dtype)
                except MistApiError:
                    return []

            # The three reads are independent: run them together (they used to wait on each other).
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="mist-directory") as pool:
                for part in pool.map(in_context(read), ("switch", "ap", "gateway")):
                    rows.extend(part)
            for d in rows:
                if not isinstance(d, dict):
                    continue
                mac = re.sub(r"[^0-9a-f]", "", str(d.get("mac") or "").lower())
                entry = {
                    "id": str(d.get("id") or ""),
                    "mac": mac,
                    "name": str(d.get("name") or d.get("hostname") or ""),
                    "type": str(d.get("type") or ""),
                    "site_id": str(d.get("site_id") or ""),
                }
                if entry["id"]:
                    out[entry["id"]] = entry
                if mac:
                    out[mac] = entry
            return out

        return self._cached_lookup("devices", build)

    def clear_cache_matching(self, *parts: str) -> None:
        if not parts:
            return
        with self._cache_lock:
            self._generation += 1
            for key in list(self._cache):
                if any(part in key for part in parts):
                    self._forget(key)
        buffer = self.__dict__.get("_event_buffer")
        # An empty part means "every cached read" (an org-level config restore). That must not also
        # throw away the incremental event buffer: config changes never alter past events, and a reset
        # re-downloads the whole lookback window against the 5,000/h budget (v0.10.22).
        if buffer is not None and any(part and part in _ORG_EVENTS_SUFFIX for part in parts):
            buffer.invalidate()

    def get_org(self, *, fresh: bool = False) -> dict:
        """The organisation object. ``fresh=True`` (the connection test) asks Mist directly and refreshes
        only this cache entry; it used to clear every cached read, so each test re-downloaded everything."""
        path = f"/api/v1/orgs/{self._org}"
        if fresh:
            if not self.configured:
                raise MistApiError("Mist connection is not configured", 409)
            url = f"{self.settings.api_host}{path}"
            key = f"GET:{url}"
            try:
                # Same single-flight key as the cached read: a dashboard read of the organisation that is
                # already in flight is shared instead of racing a second identical request.
                payload, headers = self._shared(key, lambda: self._send("GET", path, url, None, ()))
            except MistApiError as exc:
                stale = self._stale_for(exc, key)  # rate-limited: the last answer, as a cached read would
                if stale is None:
                    raise
                payload = stale.value[0]
            else:
                self._cache_put(key, CacheEntry(time.time() + self._ttl_for(path), (payload, headers)))
            return payload if isinstance(payload, dict) else {}
        result = self.get(path)
        return result if isinstance(result, dict) else {}

    def list_sites(self) -> list[dict]:
        return self._get_paged(f"/api/v1/orgs/{self._org}/sites")

    def list_org_site_stats(self) -> list[dict]:
        return self._get_paged(f"/api/v1/orgs/{self._org}/stats/sites")

    def list_org_device_stats(
        self, device_type: str = "all", *, site_id: str | None = None, mac: str | None = None
    ) -> list[dict]:
        # Mist defaults this endpoint to AP when `type` is omitted.  The org stats
        # endpoint supports site/mac filters; using them avoids downloading every
        # switch in the organization when a tool is scoped to one site.
        path = f"/api/v1/orgs/{self._org}/stats/devices"
        if device_type != "all" or site_id or mac:
            # v0.10.40: when the whole-org read (type=all; topology, inventory) is cached and current, answer
            # from it instead of a separate ~5 s read for one type / site / device.
            whole = self._cache_get(self._read_key(path, {"type": "all"}, f"paged:{_MAX_ITEMS}"), time.time())
            if whole is not None and len(whole.value) < _MAX_ITEMS:  # a truncated whole read is not complete
                self._note_hit(path)
                bare = re.sub(r"[^0-9a-f]", "", str(mac or "").lower())
                return [
                    row
                    for row in whole.value
                    if (device_type == "all" or str(row.get("type") or "") == device_type)
                    and (not site_id or str(row.get("site_id") or "") == str(site_id))
                    and (not bare or re.sub(r"[^0-9a-f]", "", str(row.get("mac") or "").lower()) == bare)
                ]
        return self._get_paged(path, {"type": device_type, "site_id": site_id, "mac": mac})

    def list_org_inventory(
        self,
        *,
        device_type: str = "all",
        vc: bool = True,
        unassigned: bool = True,
        site_id: str | None = None,
        mac: str | None = None,
        vc_mac: str | None = None,
    ) -> list[dict]:
        # Inventory also defaults to AP when `type` is omitted.
        params: dict[str, Any] = {
            "type": device_type,
            "vc": str(vc).lower(),
            "unassigned": str(unassigned).lower(),
            "site_id": site_id,
            "mac": mac,
            "vc_mac": vc_mac,
        }
        return self._get_paged(f"/api/v1/orgs/{self._org}/inventory", params)

    def list_site_devices(self, site_id: str, device_type: str = "all") -> list[dict]:
        # Site devices defaults to AP when `type` is omitted.
        return self._get_paged(f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices", {"type": device_type})

    def get_site_device(self, site_id: str, device_id: str, *, fresh: bool = False) -> dict:
        result = self.get(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/{_path_id(device_id, 'device ID')}",
            cache=not fresh,
        )
        return result if isinstance(result, dict) else {}

    def get_site_virtual_chassis(self, site_id: str, device_id: str, *, fresh: bool = False) -> dict:
        result = self.get(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/{_path_id(device_id, 'device ID')}/vc",
            cache=not fresh,
        )
        return result if isinstance(result, dict) else {}

    def get_site_setting_derived(self, site_id: str, *, fresh: bool = False) -> dict:
        """Site settings merged with templates (includes inherited ``port_usages``). Read-only."""
        result = self.get(f"/api/v1/sites/{_path_id(site_id, 'site ID')}/setting/derived", cache=not fresh)
        return result if isinstance(result, dict) else {}

    def update_site_device(self, site_id: str, device_id: str, body: dict) -> Any:
        return self.put(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/{_path_id(device_id, 'device ID')}", body
        )

    def search_org_alarms(self, *, fresh: bool = False, duration: str | None = None, limit: int = 10_000) -> list[dict]:
        path = f"/api/v1/orgs/{self._org}/alarms/search"
        default = self.settings.alarm_lookback
        if not fresh and duration and duration != default:
            # v0.10.40: a shorter window (Virtual Chassis: 1 day) is answered from the current default read
            # (newest first, so the newest `limit` alarms of any shorter window are all in it).
            want_s, have_s = duration_seconds(duration), duration_seconds(default)
            whole = self._cache_get(
                self._read_key(path, {"duration": default, "sort": "-timestamp"}, "search:10000"), time.time()
            )
            if whole is not None and want_s and have_s and want_s <= have_s:
                self._note_hit(path)
                cutoff = time.time() - want_s
                rows = []
                for row in whole.value:
                    ts = row.get("timestamp")
                    try:
                        ts = float(ts)
                    except (TypeError, ValueError):
                        continue
                    if (ts / 1000 if ts > 1e11 else ts) >= cutoff:
                        rows.append(row)
                return rows[:limit]
        return self._search(
            path,
            {"duration": duration or default, "sort": "-timestamp"},
            limit=limit,
            fresh=fresh,
        )

    def ack_alarm(self, alarm_id: str, note: str = "Acknowledged from NodeWatch") -> Any:
        # Alarm acknowledgement only changes alert state. Preserve unrelated cached topology/stats
        # so the NOC can update immediately without rebuilding the entire organization.
        path = f"/api/v1/orgs/{self._org}/alarms/{_path_id(alarm_id, 'alarm ID')}/ack"
        result = self._request("POST", path, body={"note": note}, cache=False, invalidate_all_cache=False)
        self.clear_cache_matching("/alarms/search", "/alarms/count")
        return result

    @property
    def event_buffer(self) -> RollingEventBuffer:
        """The org device-event buffer every consumer reads from (created on first use)."""
        with self._event_buffer_lock:
            if self._event_buffer is None:
                lookback = duration_seconds(self.settings.event_lookback) or 86400.0
                self._event_buffer = RollingEventBuffer(
                    self._fetch_device_events,
                    lookback_seconds=lookback,
                    poll_seconds=max(_EVENT_POLL_SECONDS, float(self.settings.cache_seconds)),
                    max_events=_EVENT_BUFFER_MAX,
                    initial_limit=10_000,
                    incremental_limit=10_000,
                    poll_multiplier=self._ttl_multiplier,
                    # Cold start: one small read of the last hour, the rest back-filled in the background
                    # (a whole day was up to ten sequential 1,000-row pages before the first dashboard).
                    quick_seconds=_EVENT_QUICK_SECONDS,
                )
            return self._event_buffer

    def _fetch_device_events(self, start: float, end: float, limit: int) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}{_ORG_EVENTS_SUFFIX}",
            {"start": int(math.floor(start)), "end": int(math.ceil(end)), "sort": "-timestamp"},
            limit=limit,
            fresh=True,  # unique start/end: never worth a cache slot
        )

    def search_org_device_events(self) -> list[dict]:
        return self.search_org_device_events_window(duration=self.settings.event_lookback, limit=10_000)

    def search_org_device_events_window(
        self, *, duration: str = "15m", limit: int = 500, fresh: bool = False
    ) -> list[dict]:
        """Org device events of the last ``duration`` (newest first).

        Served from the rolling :attr:`event_buffer` when the window fits in ``event_lookback``: at most
        one small incremental Mist read per ~30 s, shared by every consumer. ``fresh=True`` (alerting
        monitor) accepts events up to 10 s old. Longer windows still search Mist directly."""
        seconds = duration_seconds(duration)
        if seconds is not None and self.configured:
            rows = self.event_buffer.window_if_covered(
                seconds,
                limit=limit,
                max_age=_EVENT_FRESH_MAX_AGE if fresh else None,
                # While the day is back-filled after start-up, answer with what is buffered (the newest
                # events are complete) instead of searching the whole window again; the next refresh,
                # after the back-fill, is complete.
                partial_while_backfilling=True,
            )
            if rows is not None:
                return rows
            # Window longer than the lookback, or older than the buffer's gap-free coverage: ask Mist.
        return self._search(
            f"/api/v1/orgs/{self._org}/devices/events/search",
            {"duration": duration, "sort": "-timestamp"},
            limit=limit,
            fresh=fresh,
        )

    _ALARM_DEFS: tuple[float, list] | None = None

    def list_alarm_definitions(self) -> list[dict]:
        # v0.10.35: a constant table (~3 s per read in the field); kept for 12 hours per process.
        cached = MistClient._ALARM_DEFS
        if cached and time.monotonic() - cached[0] < 12 * 3600 and cached[1]:
            return list(cached[1])
        # v0.10.40: also kept on disk for a week (up to 11 s per read in the field), so a restart does not
        # make the first Command Center wait for it. Same API host only.
        disk = STATE_ROOT / "mist-alarm-defs.json"
        try:
            saved = json.loads(disk.read_text(encoding="utf-8"))
            if (
                saved.get("api_host") == self.settings.api_host
                and time.time() - float(saved.get("at") or 0) < 7 * 86400
                and isinstance(saved.get("rows"), list)
                and saved["rows"]
            ):
                MistClient._ALARM_DEFS = (time.monotonic(), saved["rows"])
                return list(saved["rows"])
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        result = self.get("/api/v1/const/alarm_defs")
        data = self._extract(result)
        rows = data if isinstance(data, list) else []
        if rows:
            MistClient._ALARM_DEFS = (time.monotonic(), rows)
            try:
                write_private_text(disk, json.dumps({"api_host": self.settings.api_host, "at": time.time(), "rows": rows}))
            except OSError:
                pass
        return rows

    def search_org_wireless_clients(
        self,
        *,
        site_id: str | None = None,
        mac: str | None = None,
        ip: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        text: str | None = None,
        duration: str = "7d",
        limit: int = 50,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/clients/search",
            {
                "site_id": site_id,
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "username": username,
                "text": text,
                "duration": duration,
                "sort": "-timestamp",
            },
            limit=limit,
        )

    def search_org_wired_clients(
        self,
        *,
        site_id: str | None = None,
        device_mac: str | None = None,
        mac: str | None = None,
        port_id: str | None = None,
        vlan: str | None = None,
        ip: str | None = None,
        text: str | None = None,
        duration: str = "7d",
        limit: int = 50,
        fresh: bool = False,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/wired_clients/search",
            {
                "site_id": site_id,
                "device_mac": device_mac,
                "mac": mac,
                "port_id": port_id,
                "vlan": vlan,
                "ip": ip,
                "text": text,
                "duration": duration,
                "sort": "-timestamp",
            },
            limit=limit,
            fresh=fresh,
        )

    def search_org_inventory(
        self,
        *,
        device_type: str | None = None,
        site_id: str | None = None,
        mac: str | None = None,
        name: str | None = None,
        serial: str | None = None,
        vc_mac: str | None = None,
        text: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        # Mist inventory search defaults to AP when type is omitted. Detective needs
        # reliable cross-device lookup, so use only the documented concrete types
        # rather than relying on an undocumented `all` value for this endpoint.
        types = [device_type] if device_type in {"ap", "switch", "gateway"} else ["ap", "switch", "gateway"]

        def fetch_type(dtype: str) -> list[dict]:
            return self._search(
                f"/api/v1/orgs/{self._org}/inventory/search",
                {
                    "type": dtype,
                    "site_id": site_id,
                    "mac": mac,
                    "name": name,
                    "serial": serial,
                    "vc_mac": vc_mac,
                    "text": text,
                    "status": status,
                    "sort": "-timestamp",
                },
                limit=limit,
            )

        if len(types) == 1:
            return fetch_type(types[0])
        rows: list[dict] = []
        with ThreadPoolExecutor(max_workers=len(types)) as pool:
            futures = [pool.submit(in_context(fetch_type), dtype) for dtype in types]
            for future in as_completed(futures):
                rows.extend(future.result())
        return rows

    def search_org_nac_clients(
        self,
        *,
        site_id: str | None = None,
        mac: str | None = None,
        username: str | None = None,
        text: str | None = None,
        duration: str = "7d",
        limit: int = 50,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/nac_clients/search",
            {"site_id": site_id, "mac": mac, "username": username, "text": text, "duration": duration},
            limit=limit,
        )

    def search_org_nac_client_events(
        self,
        *,
        site_id: str | None = None,
        mac: str | None = None,
        username: str | None = None,
        text: str | None = None,
        duration: str = "1d",
        limit: int = 50,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/nac_clients/events/search",
            {"site_id": site_id, "mac": mac, "username": username, "text": text, "duration": duration},
            limit=limit,
        )

    def search_org_ports(
        self,
        *,
        device_type: str = "switch",
        mac: str | None = None,
        port_id: str | None = None,
        neighbor_mac: str | None = None,
        neighbor_system_name: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/stats/ports/search",
            {
                "device_type": device_type,
                "mac": mac,
                "port_id": port_id,
                "neighbor_mac": neighbor_mac,
                "neighbor_system_name": neighbor_system_name,
                "sort": "-timestamp",
            },
            limit=limit,
        )

    def search_site_ports(
        self,
        site_id: str,
        *,
        device_type: str = "switch",
        mac: str | None = None,
        port_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/stats/ports/search",
            {"device_type": device_type, "mac": mac, "port_id": port_id, "sort": "-timestamp"},
            limit=limit,
        )

    def search_ports_for_topology(
        self,
        *,
        site_id: str | None = None,
        device_type: str = "switch",
        up_only: bool = False,
        limit: int = 20_000,
        fresh: bool = False,
    ) -> list[dict]:
        """Port statistics for the topology map and its live health (v0.10.21).

        Faster than :meth:`search_org_ports`: no ``sort`` (Mist sorts every matching row first),
        optionally only ``up`` ports (LLDP neighbours only exist on live ports), and once Mist reports a
        ``total`` the remaining pages are read in parallel (at most ``PARALLEL_PAGES`` at a time). Every
        page is still a counted call through the budget / 429 back-off, and the whole read is cached
        for the endpoint TTL like any other search.
        """
        if site_id:
            path = f"/api/v1/sites/{_path_id(site_id, 'site ID')}/stats/ports/search"
        else:
            path = f"/api/v1/orgs/{self._org}/stats/ports/search"
        params = {"device_type": device_type, "up": "true" if up_only else None}
        wanted = max(1, min(int(limit), _MAX_ITEMS))
        return self._cached_read(
            path, params, f"parallel:{wanted}", fresh, lambda: self._read_search_parallel(path, params, wanted)
        )

    PARALLEL_PAGES = 4

    @staticmethod
    def _row_ident(row: dict) -> tuple[str, str]:
        return (str(row.get("mac") or ""), str(row.get("port_id") or ""))

    def _read_search_parallel(self, path: str, params: dict[str, Any], wanted: int) -> list[dict]:
        """First page serially; then, when ``page`` is honoured, the rest in parallel; else follow ``next``."""
        query = {k: v for k, v in params.items() if v is not None and v != ""}
        size = min(wanted, _PAGE_LIMIT)
        first = self._request("GET", path, {**query, "limit": size})
        data = self._extract(first)
        rows = [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
        try:
            total = int(first.get("total") or 0) if isinstance(first, dict) else 0
        except (TypeError, ValueError):
            total = 0
        if len(rows) < size or len(rows) >= wanted or (total and total <= len(rows)):
            return rows[:wanted]
        template = endpoint_template(path)
        page_ok = self.__dict__.setdefault("_page_param_ok", {})
        if total and page_ok.get(template) is not False:
            pages = min(_MAX_PAGES, math.ceil(min(total, wanted) / size))
            second = self._request("GET", path, {**query, "limit": size, "page": 2})
            data2 = self._extract(second)
            batch2 = [x for x in data2 if isinstance(x, dict)] if isinstance(data2, list) else []
            seen = {self._row_ident(r) for r in rows}
            if batch2 and not any(self._row_ident(r) in seen for r in batch2[:5]):
                page_ok[template] = True
                rows.extend(batch2)
                if pages > 2 and len(batch2) >= size:

                    def fetch(page: int) -> list[dict]:
                        payload = self._request("GET", path, {**query, "limit": size, "page": page})
                        got = self._extract(payload)
                        return [x for x in got if isinstance(x, dict)] if isinstance(got, list) else []

                    with ThreadPoolExecutor(max_workers=self.PARALLEL_PAGES) as pool:
                        for batch in pool.map(in_context(fetch), range(3, pages + 1)):  # results stay in page order
                            rows.extend(batch)
                return rows[:wanted]
            page_ok[template] = False  # this endpoint ignores ``page``: use the cursor from now on
        # Cursor fallback: follow ``next`` from the first answer (serial, as before).
        nxt = first.get("next") if isinstance(first, dict) else None
        for _ in range(_MAX_PAGES):
            if not nxt or len(rows) >= wanted:
                break
            parts = urlsplit(str(nxt))
            if parts.scheme or parts.netloc or parts.path != path:
                break
            payload = self._request("GET", parts.path, dict(parse_qsl(parts.query, keep_blank_values=False)))
            got = self._extract(payload)
            batch = [x for x in got if isinstance(x, dict)] if isinstance(got, list) else []
            if not batch:
                break
            rows.extend(batch)
            nxt = payload.get("next") if isinstance(payload, dict) else None
        return rows[:wanted]

    def search_switch_port_stats(
        self, site_id: str, switch_mac: str, *, limit: int = 2000, fresh: bool = False
    ) -> list[dict]:
        """Every port-stat row of one switch (Port Toolkit / Power Guard).

        No ``sort`` parameter: sorting by timestamp is not needed for a per-switch
        view and only slows the search down. ``mac`` is the switch MAC in this API.
        """
        return self._search(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/stats/ports/search",
            {"device_type": "switch", "mac": _path_mac(switch_mac, "switch MAC")},
            limit=limit,
            fresh=fresh,
        )

    def get_site_client_stats(self, site_id: str, client_mac: str, *, wired: bool = False, fresh: bool = False) -> dict:
        # A client can remain in org inventory/search after its current site-stat
        # object has aged out. Mist returns 404 for that normal state; treat it as
        # an expected absence so diagnostics do not report a false API failure.
        result = self.get(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/stats/clients/{_path_mac(client_mac, 'client MAC')}",
            {"wired": str(bool(wired)).lower()},
            cache=not fresh,
            allowed_statuses=(404,),
        )
        return result if isinstance(result, dict) else {}

    def get_site_device_stats(self, site_id: str, device_id: str, *, fresh: bool = False) -> dict:
        """Read current statistics for one Mist device by its stable device ID.

        Detective uses this as a precise fallback for Virtual Chassis where the wired
        client may report a physical member MAC while port statistics are keyed by the
        VC/device identifier. This is read-only and does not alter any existing path.
        """
        result = self.get(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/stats/devices/{_path_id(device_id, 'device ID')}",
            cache=not fresh,
        )
        return result if isinstance(result, dict) else {}

    def troubleshoot(self, mac: str, *, site_id: str | None = None) -> dict:
        result = self.get(
            f"/api/v1/orgs/{self._org}/troubleshoot",
            {"mac": mac, "site_id": site_id},
            cache=False,
        )
        return result if isinstance(result, dict) else {"results": result}

    def list_org_admins(self) -> list[dict]:
        """Org administrators (name, email, privileges) - read-only, cached 10 minutes."""
        data = self._extract(self.get(f"/api/v1/orgs/{self._org}/admins"))
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []

    def list_org_api_tokens(self) -> list[dict]:
        """Org API tokens (name, creator, privileges, last use; never the key) - read-only, cached 10 minutes."""
        data = self._extract(self.get(f"/api/v1/orgs/{self._org}/apitokens"))
        rows = [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
        return [{k: v for k, v in row.items() if k not in {"key", "token"}} for row in rows]

    def search_audit_logs(self, duration: str = "7d") -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/logs/search",
            {"duration": duration, "sort": "-timestamp"},
            limit=10_000,
        )

    def search_site_device_events(
        self,
        site_id: str,
        *,
        mac: str | None = None,
        event_type: str | None = None,
        duration: str = "1d",
        limit: int = 100,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/events/search",
            {"mac": mac, "type": event_type, "duration": duration, "sort": "-timestamp"},
            limit=limit,
        )

    def search_site_device_config_history(
        self,
        site_id: str,
        *,
        device_type: str = "switch",
        mac: str | None = None,
        duration: str = "30d",
        limit: int = 100,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/config_history/search",
            {"type": device_type, "mac": mac, "duration": duration, "sort": "-timestamp"},
            limit=limit,
        )

    def bounce_device_port(self, site_id: str, device_id: str, ports: list[str]) -> Any:
        """Trigger Mist's documented Bounce Device Port utility."""
        return self._request(
            "POST",
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/{_path_id(device_id, 'device ID')}/bounce_port",
            body={"ports": ports},
        )

    def cable_test_from_switch(self, site_id: str, device_id: str, port_id: str) -> Any:
        """Trigger Mist's documented EX switch cable-test utility.

        The REST call starts the test. Mist streams rich TDR results on its device-command
        channel; this application records the accepted command and subsequent device/port
        state without pretending an asynchronous stream was returned synchronously.
        """
        return self._request(
            "POST",
            f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/{_path_id(device_id, 'device ID')}/cable_test",
            body={"port": port_id},
        )

    def search_org_nac_clients_any(
        self,
        *,
        status: str | None = None,
        site_id: str | None = None,
        client_type: str | None = None,
        duration: str = "1d",
        limit: int = 200,
    ) -> list[dict]:
        return self._search(
            f"/api/v1/orgs/{self._org}/nac_clients/search",
            {"status": status, "site_id": site_id, "type": client_type, "duration": duration, "sort": "-wxid"},
            limit=limit,
        )


_client: MistClient | None = None


def warm_up() -> None:
    """Start-up (v0.10.24): resolve Mist's address, open a pooled connection and read the organisation
    and the first hour of device events in the background while the browser opens, so the first page
    finds them cached (single-flight shares a read still in progress). Never raises.

    v0.10.40: also the reads most pages open with (site list, site and device statistics, device
    inventory, open alarms, alarm definitions), four at a time, so the first visit to the Command Center,
    Virtual Chassis, Power Guard, Inventory or Topology finds them ready. About ten calls per start."""

    def run() -> None:
        try:
            client = get_mist_client()
            if not client.configured:
                return
            client.get_org()
            reads = (
                client.list_sites,
                client.list_org_site_stats,
                lambda: client.search_org_inventory(limit=50_000),
                client.search_org_alarms,
                client.list_alarm_definitions,
                lambda: client.list_org_inventory(device_type="switch", vc=True, unassigned=True),
                lambda: client.list_org_device_stats("all"),
            )

            def safe(fn) -> None:
                try:
                    fn()
                except Exception:  # noqa: BLE001 - the page reads again and reports any error itself
                    pass

            with ThreadPoolExecutor(max_workers=4, thread_name_prefix="mist-warm-up") as pool:
                pool.submit(safe, client.event_buffer.refresh_if_needed)
                list(pool.map(safe, reads))
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=run, name="mist-warm-up", daemon=True).start()


_CLIENT_LOCK = threading.Lock()


def get_mist_client() -> MistClient:
    # Double-checked: the start-up warm-up thread and the first page requests ask at the same moment;
    # two clients would each build caches and an event buffer and one would be thrown away.
    global _client
    client = _client
    if client is None:
        with _CLIENT_LOCK:
            if _client is None:
                _client = MistClient()
            client = _client
    return client


def reset_mist_client(settings: Settings | None = None) -> MistClient:
    """Drop the shared session/cache after configuration changes."""
    global _client
    reset_connection_pool()
    with _CLIENT_LOCK:
        _client = MistClient(settings=settings)
    return _client
