from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlparse

WRITE_REQUEST_TOKEN = secrets.token_urlsafe(32)
OWNER_SESSION_COOKIE = "nodewatch_owner"

OWNER_SESSION_IDLE_SECONDS = 30 * 60
OWNER_SESSION_MAX_SECONDS = 8 * 60 * 60

# token -> (created_at, last_used_at) on the monotonic clock
_owner_sessions: dict[str, tuple[float, float]] = {}
_owner_sessions_lock = threading.Lock()

_SENSITIVE_KEY = re.compile(
    r"(^|[_-])(token|secret|password|passwd|passphrase|psk|pre[_-]?shared[_-]?key|private[_-]?key|api[_-]?key|auth[_-]?key|enc[_-]?key|community|credential|authorization)([_-]|$)",
    re.IGNORECASE,
)

_SECRET_KEY_NAMES = (
    r"token|secret|password|passwd|passphrase|psk|pre[_ -]?shared[_ -]?key|private[_ -]?key|"
    r"api[_ -]?key|apikey|auth[_ -]?key|authorization|community|client[_ -]?secret|"
    r"access[_ -]?token|refresh[_ -]?token|webhook[_ -]?url|hec[_ -]?token"
)
# Matches key=value, key: value and JSON/Python-literal forms such as
# "password": "x" or 'psk': 'x'. Group 1 keeps the key, its quotes and the
# separator; group 2 is the value (quoted or bare).
_TEXT_SECRET = re.compile(
    r"(?i)((?<![A-Za-z0-9_])[\"']?(?:" + _SECRET_KEY_NAMES + r")[\"']?\s*[:=]\s*)"
    r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s,;}\]]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-]{16,}={0,2}")
_BASIC_SECRET = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]{20,}={0,2}")
_JWT_SECRET = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|token|api_key|apikey|client_secret|secret|password)=)([^&#\s]+)"
)


def redact_text(value: Any, *known_secrets: str) -> str:
    """Best-effort sanitization for diagnostic/error strings.

    Known values are removed first, then common credential formats are scrubbed so
    future providers inherit safe logging behavior without each implementation having
    to remember every token format.
    """
    text = str(value or "")
    for secret in known_secrets:
        secret = str(secret or "")
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***REDACTED***")
    text = _BEARER_SECRET.sub("Bearer ***REDACTED***", text)
    text = _BASIC_SECRET.sub("Basic ***REDACTED***", text)
    text = _JWT_SECRET.sub("***REDACTED-JWT***", text)
    text = _QUERY_SECRET.sub(lambda m: f"{m.group(1)}***REDACTED***", text)
    return _TEXT_SECRET.sub(_redact_key_value, text)


def _redact_key_value(match: re.Match) -> str:
    prefix, value = match.group(1), match.group(2)
    quote = value[0] if value[:1] in {'"', "'"} else ""
    return f"{prefix}{quote}***REDACTED***{quote}"


def contains_secret_material(value: Any, *known_secrets: str) -> bool:
    """Return True when text still appears to contain credential material.

    The redaction pass is intentionally idempotent: if applying it would still
    change the text, the text was not fully sanitized yet.
    """
    text = str(value or "")
    for secret in known_secrets:
        secret = str(secret or "")
        if secret and len(secret) >= 4 and secret in text:
            return True
    return redact_text(text, *known_secrets) != text


def _prune_owner_sessions(now: float) -> None:
    for token, (created, last_used) in list(_owner_sessions.items()):
        if now - last_used > OWNER_SESSION_IDLE_SECONDS or now - created > OWNER_SESSION_MAX_SECONDS:
            _owner_sessions.pop(token, None)


def create_owner_session() -> str:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _owner_sessions_lock:
        _prune_owner_sessions(now)
        _owner_sessions[token] = (now, now)
    return token


def valid_owner_session(token: str | None) -> bool:
    """True for a live owner session; sessions expire after 30 min idle or 8 h total."""
    if not token:
        return False
    now = time.monotonic()
    with _owner_sessions_lock:
        _prune_owner_sessions(now)
        # Compare in constant time against known tokens. The set is normally tiny.
        for candidate, (created, _) in _owner_sessions.items():
            if hmac.compare_digest(token, candidate):
                _owner_sessions[candidate] = (created, now)
                return True
    return False


def revoke_owner_session(token: str | None) -> None:
    if not token:
        return
    with _owner_sessions_lock:
        _owner_sessions.pop(token, None)


def redact_sensitive(value: Any) -> Any:
    """Recursively redact credential-like values before they reach local audit/log files."""
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY.search(key_text):
                out[key] = "***REDACTED***"
            else:
                out[key] = redact_sensitive(item)
        return out
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    return value


def validate_http_url(value: str, *, require_https: bool = False) -> str:
    text = (value or "").strip()
    parsed = urlparse(text)
    allowed = {"https"} if require_https else {"http", "https"}
    if parsed.scheme.lower() not in allowed or not parsed.hostname:
        scheme_text = "https" if require_https else "http(s)"
        raise ValueError(f"Destination must be a valid {scheme_text} URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in destination URLs")
    if parsed.fragment:
        raise ValueError("Destination URLs must not contain a fragment")
    return text


# ---------------------------------------------------------------------------
# Launcher identity proof
#
# A per-install random key lives at <data root>/state/launcher-identity.key (hex,
# 64 chars; created by whichever of the native launcher or backend starts first,
# inside the user's private %LOCALAPPDATA% profile). Before reusing an already-
# running backend, the launcher sends a random challenge to
# /api/status?probe=true&challenge=<hex>; a genuine NodeWatch backend answers with
# identity_proof = HMAC-SHA256(key, "nodewatch-identity:v2:<port>:" + challenge) in hex,
# where <port> is the port the backend itself listens on. Binding the port (v0.10.22)
# stops another listener from relaying the challenge to the real backend and passing
# its answer off as its own. Keep in sync with release/native_launcher.go.
#
# Fresh launches use launch_proof(): the launcher keeps the per-launch nonce secret
# (it reaches only the child's environment) and sends a random challenge; the backend
# answers HMAC-SHA256(nonce, "nodewatch-launch:v2:<port>:" + challenge). Before
# v0.10.22 the nonce itself was sent to every port, so any listener could answer.
# ---------------------------------------------------------------------------
IDENTITY_KEY_FILENAME = "launcher-identity.key"
_IDENTITY_CHALLENGE = re.compile(r"^[0-9a-f]{32,128}$")


def install_identity_key(state_root) -> bytes:
    from pathlib import Path

    path = Path(state_root) / IDENTITY_KEY_FILENAME
    try:
        text = path.read_text(encoding="ascii").strip()
        if re.fullmatch(r"[0-9a-f]{64}", text):
            return bytes.fromhex(text)
    except (OSError, ValueError):
        pass
    from app.core.file_utils import write_private_text

    key = secrets.token_bytes(32)
    write_private_text(path, key.hex())
    return key


def _valid_port(port) -> int | None:
    try:
        value = int(port)
    except (TypeError, ValueError):
        return None
    return value if 1 <= value <= 65535 else None


def identity_proof(state_root, challenge: str, port) -> str | None:
    """Per-install-key proof for a backend listening on ``port`` (its own bound port)."""
    challenge = str(challenge or "").strip().lower()
    port = _valid_port(port)
    if port is None or not _IDENTITY_CHALLENGE.match(challenge):
        return None
    key = install_identity_key(state_root)
    message = f"nodewatch-identity:v2:{port}:{challenge}".encode("ascii")
    return hmac.new(key, message, "sha256").hexdigest()


def launch_proof(nonce: str, challenge: str, port) -> str | None:
    """Per-launch proof: HMAC(nonce, "nodewatch-launch:v2:<port>:<challenge>"); None when unusable."""
    nonce = str(nonce or "").strip()
    challenge = str(challenge or "").strip().lower()
    port = _valid_port(port)
    if not nonce or port is None or not _IDENTITY_CHALLENGE.match(challenge):
        return None
    message = f"nodewatch-launch:v2:{port}:{challenge}".encode("ascii")
    return hmac.new(nonce.encode("utf-8"), message, "sha256").hexdigest()
