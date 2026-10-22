"""Validation of the shared triage folder path typed in Settings."""

from __future__ import annotations

import os
import re

MAX_PATH = 240
_UNC = re.compile(r"^\\\\(?P<server>[A-Za-z0-9._\-$]+)\\(?P<share>[^\\/:*?\"<>|]+)(\\[^\\/:*?\"<>|]+)*\\?$")
_DRIVE = re.compile(r"^[A-Za-z]:\\([^\\/:*?\"<>|]+\\?)*$")
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def validate_folder_path(value: object, *, os_name: str | None = None) -> str:
    """Return the normalised path or raise ValueError with a readable reason.

    Windows: an absolute UNC path (``\\\\fileserver\\NodeWatch\\triage``) or a drive path
    (``S:\\NodeWatch\\triage``). Forward slashes are accepted and turned into backslashes. Rejected: relative
    paths, ``..`` / ``.`` segments, device paths (``\\\\?\\``, ``\\\\.\\``), URLs, wildcard characters and
    control characters. Elsewhere (development / tests): an absolute POSIX path without ``..``.
    """
    os_name = os_name or os.name
    raw = str(value if value is not None else "").strip().strip('"').strip()
    if not raw:
        raise ValueError("Enter the shared folder path, for example \\\\fileserver\\NodeWatch\\triage")
    if len(raw) > MAX_PATH:
        raise ValueError(f"The path is too long ({MAX_PATH} characters max)")
    if _BAD_CHARS.search(raw):
        raise ValueError("The path contains control characters")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", raw) or raw.lower().startswith("file:"):
        raise ValueError("Enter a folder path, not a URL")
    if os_name == "nt":
        path = raw.replace("/", "\\")
        if path.startswith("\\\\?\\") or path.startswith("\\\\.\\"):
            raise ValueError("Device paths (\\\\?\\ or \\\\.\\) are not allowed")
        parts = [p for p in path.split("\\") if p]
        if any(p in {".", ".."} for p in parts):
            raise ValueError("The path must not contain '.' or '..' segments")
        if not (_UNC.match(path) or _DRIVE.match(path)):
            raise ValueError(
                "Use a full UNC path (\\\\server\\share\\folder) or a drive path (S:\\folder); relative paths are not allowed"
            )
        if any(p.endswith((" ", ".")) for p in parts[1:]):
            raise ValueError("Folder names must not end with a space or a dot")
        return path.rstrip("\\") if not _DRIVE.match(path) or len(path) > 3 else path
    if not raw.startswith("/") or raw.startswith("//"):
        raise ValueError("Use an absolute folder path")
    parts = [p for p in raw.split("/") if p]
    if any(p in {".", ".."} for p in parts):
        raise ValueError("The path must not contain '.' or '..' segments")
    if re.search(r"[*?\"<>|]", raw):
        raise ValueError("The path contains characters that are not allowed in folder names")
    return "/" + "/".join(parts)
