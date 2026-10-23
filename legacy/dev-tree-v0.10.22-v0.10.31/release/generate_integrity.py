"""Regenerate integrity.json and pin its hash into the native launcher.

Run from anywhere after the last change to the release tree, i.e. after
tools/stage_runtime.py (bundled interpreter -> runtime/python/) and after the backend
host has been built and signed into runtime/NodeWatchBackend.exe (see
docs/RELEASE_PROCESS.md):

    python release/generate_integrity.py            # write integrity.json, print its hash
    python release/generate_integrity.py --update-launcher   # also patch native_launcher.go

Then rebuild NodeWatch-v<version>.exe from release/native_launcher.go and sign it.

What is covered (must match release/native_launcher.go):
  * every file under app/ except __pycache__/ and *.pyc
  * requirements.txt, requirements.lock, requirements-optional.txt and requirements-optional.lock
  * every file under branding/ (the launcher parses startup.bmp before the backend starts)
  * every file under runtime/ when present: the bundled interpreter runtime/python/**
    (about 570 files / 34 MB after trimming) and the backend host runtime/NodeWatchBackend.exe,
    each listed individually with its path relative to _internal (e.g.
    runtime/python/python312.dll). The launcher hashes every listed file on each start
    (~35 MB of SHA-256, well under a second), so no tree hash is needed.
The launcher refuses to start when a listed file changed, when runtime/NodeWatchBackend.exe
exists but is not listed. Any unlisted file under runtime/ or app/ (v0.10.22: any type, not only
code) is moved to the quarantine folder, as are unlisted .py/.pyc/.pyd/.pth/.dll files in the
top-level folder (e.g. left over from an older release).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "release" / "native_launcher.go"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def app_build() -> str:
    text = (ROOT / "app" / "core" / "version.py").read_text(encoding="utf-8")
    match = re.search(r'APP_BUILD\s*=\s*"([^"]+)"', text)
    if not match:
        sys.exit("APP_BUILD not found in app/core/version.py")
    return match.group(1)


def collect() -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted((ROOT / "app").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            files[path.relative_to(ROOT).as_posix()] = sha256(path)
    for name in ("requirements.txt", "requirements.lock", "requirements-optional.txt", "requirements-optional.lock"):
        if (ROOT / name).is_file():
            files[name] = sha256(ROOT / name)
    # v0.10.22: the launcher parses branding/startup.bmp (LoadImageW) before the backend starts,
    # so every branding file is hash-checked too.
    branding = ROOT / "branding"
    if branding.is_dir():
        for path in sorted(branding.rglob("*")):
            if path.is_file():
                files[path.relative_to(ROOT).as_posix()] = sha256(path)
    runtime = ROOT / "runtime"
    if runtime.is_dir():
        # Everything under runtime/ is listed (the launcher rejects any unlisted file there).
        for path in sorted(runtime.rglob("*")):
            if path.is_file():
                files[path.relative_to(ROOT).as_posix()] = sha256(path)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--update-launcher", action="store_true", help="write the manifest hash into native_launcher.go"
    )
    args = parser.parse_args()

    manifest = {"build": app_build(), "files": collect()}
    out = ROOT / "integrity.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    digest = sha256(out)
    print(f"integrity.json: {len(manifest['files'])} files, build {manifest['build']}")
    print(f"manifest sha256: {digest}")
    runtime_files = [name for name in manifest["files"] if name.startswith("runtime/")]
    if runtime_files:
        runtime_bytes = sum((ROOT / name).stat().st_size for name in runtime_files)
        print(f"runtime/: {len(runtime_files)} files, {runtime_bytes / 1_000_000:.1f} MB")
        stray = [n for n in runtime_files if "__pycache__" in n.split("/") or n.endswith(".pyc")]
        if stray:
            print(f"WARNING: {len(stray)} cache files under runtime/ (e.g. {stray[0]}); re-run tools/stage_runtime.py")
        if (ROOT / "runtime" / "python" / "python.exe").is_file() and not (
            ROOT / "runtime" / "NodeWatchBackend.exe"
        ).is_file():
            print(
                "WARNING: runtime/python is staged but runtime/NodeWatchBackend.exe (release/backend_host) is not built; "
                "the backend will run as python.exe."
            )
    if not (ROOT / "requirements.lock").is_file():
        print(
            "ERROR-LEVEL WARNING: requirements.lock is missing - since v0.10.22 the launcher REFUSES to install "
            "dependencies without it, so this package will not start. Run release\\Update-Lockfile.ps1 first."
        )
    if (ROOT / "requirements-optional.txt").is_file() and not (ROOT / "requirements-optional.lock").is_file():
        print(
            "WARNING: requirements-optional.lock is missing - the optional SNMP components will not be installed. "
            "Run release\\Update-Lockfile.ps1 first."
        )

    if args.update_launcher:
        source = LAUNCHER.read_text(encoding="utf-8")
        updated, count = re.subn(r'(manifestSHA256\s*=\s*")[0-9a-f]{64}(")', rf"\g<1>{digest}\g<2>", source)
        if count != 1:
            sys.exit("manifestSHA256 constant not found exactly once in native_launcher.go")
        version = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', (ROOT / "app/core/version.py").read_text()).group(1)
        updated = re.sub(r'(appVersion\s*=\s*")[^"]+(")', rf"\g<1>{version}\g<2>", updated)
        updated = re.sub(r'(appBuild\s*=\s*")[^"]+(")', rf"\g<1>{manifest['build']}\g<2>", updated)
        LAUNCHER.write_text(updated, encoding="utf-8", newline="\n")
        print("native_launcher.go updated (manifestSHA256, appVersion, appBuild)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
