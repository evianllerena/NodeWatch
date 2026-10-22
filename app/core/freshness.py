"""Whether cached answers may be served stale while they refresh (v0.10.40).

Caches that answer with a just-expired value and refresh it in the background (MistClient, the
EdgeConnect connector) check :func:`stale_allowed`. Code that must decide on current data (the alerting
monitor) runs inside :func:`no_stale`; :func:`in_context` carries that into worker threads.
"""

from __future__ import annotations

import contextlib
import contextvars

_NO_STALE: contextvars.ContextVar[bool] = contextvars.ContextVar("nodewatch_no_stale", default=False)


def stale_allowed() -> bool:
    return not _NO_STALE.get()


@contextlib.contextmanager
def no_stale():
    token = _NO_STALE.set(True)
    try:
        yield
    finally:
        _NO_STALE.reset(token)


def in_context(fn):
    """``fn`` bound to the caller's context (``ThreadPoolExecutor`` does not carry it to its threads)."""
    ctx = contextvars.copy_context()
    # A Context can be entered by one thread at a time: every call runs in its own copy of it.
    return lambda *a, **k: ctx.copy().run(fn, *a, **k)
