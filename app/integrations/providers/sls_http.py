"""Old location of the keep-alive HTTPS client; it lives in ``app.core.http_pool`` since v0.10.45."""

from app.core.http_pool import KeepAliveOpener, PooledResponse, ResponseTooLarge  # noqa: F401
