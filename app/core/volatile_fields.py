"""Values that change on every read and are not configuration (v0.10.24) - one shared list.

Used wherever two versions of a vendor object are compared (Config Backups live-vs-snapshot,
snapshot-vs-snapshot, template drift, the Activity Log's before/after diff) so that a re-read never
shows up as a change, and wherever such values are displayed, so a signed link's credential never
reaches the page.

* Timestamps and run-time state: ``modified_time``, ``created_time``, ``last_seen``, ``uptime`` …
* Signed / expiring URLs: any URL whose query carries a credential or an expiry (``jwt=``, ``token=``,
  ``signature=``, ``sig=``, ``X-Amz-*``, ``Expires=``, Azure SAS ``se=``/``sp=``/``sv=`` …), and keys
  that only ever hold such links (``image1_url``, ``*_download_url``, ``*_signed_url``). Two signed
  links to the same file (same scheme, host and path) are the same value; a different file is a real
  change and is shown with its query credentials replaced by ``•••``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

# Never configuration: bookkeeping timestamps and run-time readings.
VOLATILE_KEYS = frozenset(
    {
        "modified_time",
        "created_time",
        "last_modified",
        "for_site",
        "_ttl",
        "last_seen",
        "uptime",
        "timestamp",
    }
)
# Run-time state that configuration comparisons ignore (an object's live state is not its config).
STATE_KEYS = frozenset({"status", "connected"})
_VOLATILE_KEY_RE = re.compile(
    r"^(image\d*_url|[a-z0-9_]*_signed_url|[a-z0-9_]*download_url|[a-z0-9_]*_url_expires?)$", re.I
)
_SIGNED_PARAM = r"(?:jwt|token|access_token|id_token|signature|sig|x-amz-[a-z0-9-]+|expires|se|sp|sv|skoid|sktid|policy|key-pair-id)"
_SIGNED_QUERY_RE = re.compile(rf"[?&]{_SIGNED_PARAM}=", re.I)
_SIGNED_VALUE_RE = re.compile(rf"([?&]{_SIGNED_PARAM}=)[^&#\s\"'<>]*", re.I)
MASK = "•••"


def is_volatile_key(key: Any, *, include_state: bool = False) -> bool:
    """A key whose value is never configuration (timestamps, signed-link fields; ``status`` /
    ``connected`` too when ``include_state``)."""
    k = str(key)
    if k in VOLATILE_KEYS or (include_state and k in STATE_KEYS):
        return True
    return bool(_VOLATILE_KEY_RE.match(k))


def is_signed_url(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value[:8].lower().startswith(("http://", "https://"))
        and bool(_SIGNED_QUERY_RE.search(value))
    )


def _url_base(value: str) -> tuple[str, str, str]:
    try:
        parts = urlsplit(value)
    except ValueError:
        return ("", "", value)
    return (parts.scheme.lower(), parts.netloc.lower(), parts.path)


def same_signed_link(before: Any, after: Any) -> bool:
    """Two signed links to the same file (only the signature / expiry differ)."""
    return is_signed_url(before) and is_signed_url(after) and _url_base(before) == _url_base(after)


def is_volatile_change(key: Any, before: Any, after: Any, *, include_state: bool = False) -> bool:
    """True when ``before`` → ``after`` under ``key`` is not a configuration change."""
    return is_volatile_key(key, include_state=include_state) or same_signed_link(before, after)


def redact_signed_url(text: Any) -> Any:
    """``https://x/download?jwt=eyJ…&a=1`` → ``https://x/download?jwt=•••&a=1`` (non-strings unchanged)."""
    if not isinstance(text, str) or "=" not in text:
        return text
    return _SIGNED_VALUE_RE.sub(lambda m: m.group(1) + MASK, text)


def redact_signed_urls(value: Any, *, _depth: int = 0) -> Any:
    """Copy of ``value`` with every signed link's credentials masked (dicts / lists walked)."""
    if _depth > 40:
        return value
    if isinstance(value, str):
        return redact_signed_url(value)
    if isinstance(value, dict):
        return {k: redact_signed_urls(v, _depth=_depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_signed_urls(v, _depth=_depth + 1) for v in value]
    return value
