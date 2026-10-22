from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

_THREAD_LOCKS: dict[str, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path.resolve()).lower() if os.name == "nt" else str(path.resolve())
    with _THREAD_LOCKS_GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = _THREAD_LOCKS[key] = threading.RLock()
        return lock


def _chmod_private(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def write_private_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Atomically replace a user-data file and request owner-only mode where supported.

    Each write uses its own uniquely named temporary file in the same folder, so two
    concurrent writers can never interleave through a shared ``.tmp`` file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        _chmod_private(tmp)
        # Windows can briefly refuse the rename while antivirus/indexers hold the target.
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    _chmod_private(path)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Exclusive lock for read-modify-write of ``path`` across threads and processes.

    Uses a sidecar ``<name>.lock`` file with ``msvcrt.locking`` on Windows and
    ``fcntl.flock`` elsewhere, plus an in-process lock (OS file locks are per process).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with _thread_lock(path):
        with open(lock_path, "a+b") as handle:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                while True:
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.02)
                try:
                    yield
                finally:
                    handle.seek(0)
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


_READ_ATTEMPTS = 5
_READ_RETRY_S = 0.1


def _read_existing_json(path: Path, default: Any) -> Any:
    """Current value for a read-modify-write: ``default`` only when the file does not exist.

    On Windows antivirus, backup or indexing tools briefly hold files open; ``read_json`` then
    returned ``default`` and the update rewrote e.g. connectors.json as ``{}`` plus one entry,
    wiping every other saved connection. A file that exists but cannot be read is retried with
    back-off and then raises: the update is refused instead of destroying data. A file that is
    readable but not JSON after the retries (truly corrupt) is set aside as ``<name>.corrupt-<time>``
    so it is not lost, and the update starts from ``default``.
    """
    last_exc: Exception | None = None
    for attempt in range(_READ_ATTEMPTS):
        if not path.exists():
            return default
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return default
        except OSError as exc:  # locked / access denied: transient on Windows
            last_exc = exc
        else:
            if not raw.strip():
                return default  # empty file: nothing to preserve
            try:
                return json.loads(raw)
            except ValueError as exc:  # possibly read mid-write by a non-atomic writer: retry
                last_exc = exc
        time.sleep(_READ_RETRY_S * (attempt + 1))
    if isinstance(last_exc, ValueError):
        backup = path.with_name(f"{path.name}.corrupt-{time.strftime('%Y%m%dT%H%M%S')}")
        try:
            os.replace(path, backup)
        except OSError as exc:
            raise OSError(f"{path.name} is not valid JSON and could not be set aside: {exc}") from exc
        return default
    raise OSError(f"{path.name} exists but could not be read; not overwriting it ({last_exc})") from last_exc


def locked_json_update(path: Path, update: Callable[[Any], Any], *, default: Any = None) -> Any:
    """Read JSON, apply ``update`` (returning the new value), and write it back atomically.

    Concurrent callers are serialized so one save can no longer overwrite another's
    changes. If ``update`` returns ``None`` the file is removed.
    """
    path = Path(path)
    with file_lock(path):
        current = _read_existing_json(path, default)
        new_value = update(current)
        if new_value is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        else:
            write_private_text(path, json.dumps(new_value, indent=2))
        return new_value


def append_jsonl_rotating(path: Path, record: dict, *, max_bytes: int = 2_000_000) -> None:
    """Append one JSON line, rotating to ``<name>.1`` past ``max_bytes``, under one lock.

    Several writers share the diagnostics logs; rotating without a lock could drop or
    double-rotate lines.
    """
    _append_lines(Path(path), [json.dumps(record, separators=(",", ":")) + "\n"], max_bytes)


def _append_lines(path: Path, lines: list[str], max_bytes: int) -> None:
    with file_lock(path):
        try:
            if path.exists() and path.stat().st_size > max_bytes:
                rotated = path.with_name(path.name + ".1")
                try:
                    rotated.unlink()
                except FileNotFoundError:
                    pass
                os.replace(path, rotated)
        except OSError:
            pass
        with path.open("a", encoding="utf-8") as fh:
            fh.write("".join(lines))


# ---- background JSONL writer (v0.10.23) ---------------------------------------------------------
# Diagnostics lines (one per API call) used to be appended synchronously on the request thread: a
# lock-file open, an OS lock, a stat and an append per line, serialised across every thread. They are
# now queued and written in batches by one daemon thread. Lines are best effort (diagnostics only);
# the queue is bounded so a stuck disk can never grow memory.
_ASYNC_QUEUE_MAX = 10_000
_async_lock = threading.Lock()
_async_pending: dict[tuple[str, int], list[str]] = {}
_async_count = 0
_async_wake = threading.Event()
_async_busy = threading.Event()
_async_thread: threading.Thread | None = None


def _async_writer() -> None:
    global _async_count
    while True:
        _async_wake.wait(timeout=2.0)
        _async_wake.clear()
        time.sleep(0.2)  # let a burst collect into one write
        with _async_lock:
            batches = dict(_async_pending)
            _async_pending.clear()
            _async_count = 0
            _async_busy.set()
        try:
            for (name, max_bytes), lines in batches.items():
                try:
                    _append_lines(Path(name), lines, max_bytes)
                except Exception:  # noqa: BLE001 - diagnostics must never break anything
                    pass
        finally:
            _async_busy.clear()


def append_jsonl_rotating_async(path: Path, record: dict, *, max_bytes: int = 2_000_000) -> None:
    """Queue one JSON line for :func:`append_jsonl_rotating` on a background thread (never blocks)."""
    global _async_thread, _async_count
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with _async_lock:
        if _async_count >= _ASYNC_QUEUE_MAX:
            return  # drop rather than grow without bound
        _async_pending.setdefault((str(path), int(max_bytes)), []).append(line)
        _async_count += 1
        if _async_thread is None or not _async_thread.is_alive():
            _async_thread = threading.Thread(target=_async_writer, name="jsonl-writer", daemon=True)
            _async_thread.start()
    _async_wake.set()


def flush_async_jsonl(timeout: float = 2.0) -> None:
    """Wait (briefly) until queued diagnostics lines are written (support export, tests)."""
    deadline = time.monotonic() + timeout
    _async_wake.set()
    while time.monotonic() < deadline:
        with _async_lock:
            if not _async_count and not _async_busy.is_set():
                break
        time.sleep(0.05)
