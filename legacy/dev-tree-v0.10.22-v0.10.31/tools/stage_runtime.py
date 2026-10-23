"""Stage the bundled Python interpreter into ``_internal/runtime/python/``.

Release-build helper (run on the build machine, not on user PCs). It extracts a
python-build-standalone Windows ``install_only_stripped`` archive, drops the parts
NodeWatch never uses, and leaves a small interpreter the launcher prefers over any
Python installed on the PC:

    python tools/stage_runtime.py --archive cpython-3.12.15+20261003-x86_64-pc-windows-msvc-install_only_stripped.tar.gz \
        --sha256 6fba7f2ae506facf41d457ea8293c7497910a675c69a4e954875169410a50402

The launcher then creates its private venv from ``runtime\\python\\python.exe`` and
installs the pinned requirements into it (so the PC still needs internet on first
start, but no Python install). Everything under ``runtime/`` is listed file by file in
integrity.json, so run release/generate_integrity.py AFTER this script and after the
backend host (runtime/NodeWatchBackend.exe) has been built and signed.

The staged folder is a build output: it is git-ignored and must never be committed.

Trimmed (not needed to run NodeWatch, create a venv or pip-install wheels):
  tcl/, include/, libs/ (import libraries), Lib/idlelib, Lib/tkinter, Lib/turtledemo,
  Lib/turtle.py, Lib/lib2to3, any test/tests/idle_test folder under Lib/, every
  __pycache__/ and *.pyc, *.pdb, the CPython self-test and Tk extension modules in DLLs/,
  and Lib/site-packages/pip* (pip is installed into the venv from the wheel that
  Lib/ensurepip/_bundled carries, which is therefore kept).
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEST = ROOT / "runtime" / "python"

DROP_TOP_DIRS = {"tcl", "include", "libs"}
DROP_LIB_DIRS = {"idlelib", "tkinter", "turtledemo", "lib2to3", "test"}
DROP_ANY_DIRS = {"__pycache__"}
DROP_LIB_SUBTREE_DIRS = {"test", "tests", "idle_test"}
DROP_LIB_FILES = {"turtle.py"}
DROP_DLLS = {"_tkinter.pyd", "tcl86t.dll", "tk86t.dll", "_ctypes_test.pyd"}
DROP_SUFFIXES = {".pyc", ".pdb"}

# Files the launcher / backend host / venv creation depend on. Staging fails without them.
REQUIRED = (
    "python.exe",
    "python312.dll",
    "python3.dll",
    "vcruntime140.dll",
    "Lib/os.py",
    "Lib/encodings/__init__.py",
    "Lib/venv/__init__.py",
    "Lib/venv/scripts/nt/python.exe",
    "Lib/ensurepip/__init__.py",
    "DLLs/_ssl.pyd",
    "DLLs/_socket.pyd",
    "DLLs/libssl-3-x64.dll",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_trimmed(rel: PurePosixPath) -> bool:
    """``rel`` is relative to the interpreter root (the archive's ``python/`` folder)."""
    parts = rel.parts
    if not parts:
        return False
    if parts[0] in DROP_TOP_DIRS:
        return True
    if any(p in DROP_ANY_DIRS for p in parts):
        return True
    if rel.suffix.lower() in DROP_SUFFIXES:
        return True
    if parts[0] == "Lib":
        if len(parts) >= 2 and parts[1] in DROP_LIB_DIRS:
            return True
        if len(parts) == 2 and parts[1] in DROP_LIB_FILES:
            return True
        if any(p in DROP_LIB_SUBTREE_DIRS for p in parts[1:-1]):
            return True
        if len(parts) >= 3 and parts[1] == "site-packages" and parts[2].lower().startswith("pip"):
            return True
    if parts[0] == "DLLs" and len(parts) == 2:
        name = parts[1]
        if name in DROP_DLLS or name.startswith("_test"):
            return True
    return False


def _safe_member_path(name: str) -> PurePosixPath | None:
    """Strip the leading ``python/`` folder; reject anything that escapes it."""
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or not p.parts or p.parts[0] != "python":
        return None
    return PurePosixPath(*p.parts[1:])


def stage(archive: Path, dest: Path, expected_sha256: str | None) -> tuple[int, int]:
    actual = sha256(archive)
    if expected_sha256:
        if actual.lower() != expected_sha256.strip().lower():
            raise SystemExit(f"archive sha256 {actual} does not match the expected {expected_sha256}; refusing to stage")
    else:
        print(f"WARNING: no --sha256 given; archive sha256 is {actual} - compare it with the release SHA256SUMS")

    if dest.exists():
        if any(dest.iterdir()) and not (dest / "python.exe").is_file():
            raise SystemExit(f"{dest} exists, is not empty and does not look like a staged runtime; refusing to delete it")
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    count = 0
    size = 0
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            rel = _safe_member_path(member.name)
            if rel is None:
                if member.name.rstrip("/") in ("python", "."):
                    continue
                raise SystemExit(f"unexpected path in archive: {member.name!r}")
            if not rel.parts or member.isdir():
                continue
            if not member.isfile():
                # Links/devices are never needed and could point outside dest.
                raise SystemExit(f"refusing non-regular archive member: {member.name!r}")
            if is_trimmed(rel):
                continue
            target = dest.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                raise SystemExit(f"cannot read archive member {member.name!r}")
            with src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
            size += member.size

    missing = [r for r in REQUIRED if not (dest / r).is_file()]
    if not list((dest / "Lib" / "ensurepip" / "_bundled").glob("pip-*.whl")):
        missing.append("Lib/ensurepip/_bundled/pip-*.whl")
    if missing:
        raise SystemExit("staged runtime is missing required files: " + ", ".join(missing))
    return count, size


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive", required=True, type=Path, help="python-build-standalone *.tar.gz")
    parser.add_argument("--sha256", help="expected SHA-256 of the archive (from the release SHA256SUMS)")
    parser.add_argument(
        "--dest", type=Path, default=DEFAULT_DEST, help=f"staging folder (default: {DEFAULT_DEST})"
    )
    args = parser.parse_args(argv)
    count, size = stage(args.archive, args.dest, args.sha256)
    print(f"staged {count} files, {size / 1_000_000:.1f} MB into {args.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
