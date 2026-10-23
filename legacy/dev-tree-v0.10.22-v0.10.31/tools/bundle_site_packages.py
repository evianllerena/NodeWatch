"""Pre-install every Python package NodeWatch needs into runtime/site-packages (v0.10.22).

With the packages inside the release, a user's PC never runs pip: no internet, no proxy or
mirror settings, no lock file and no first-start wait. Every bundled file is listed in
integrity.json (generate_integrity.py lists everything under runtime/), so the launcher
hash-checks the packages on every start exactly like the application code.

Run on the release build machine (needs internet access to PyPI or your mirror), from _internal:

    python tools/bundle_site_packages.py
    python release/generate_integrity.py --update-launcher
    (then build and sign NodeWatch.exe, docs/RELEASE_PROCESS.md)

Any Python 3.10+ works, on Windows, Linux or macOS: wheels are fetched for the bundled
interpreter's platform (win_amd64, CPython 3.12), never for the machine running this script.
No Python installed? Use the bundled one: ``runtime\\python\\python.exe tools\\bundle_site_packages.py``.

When requirements.lock / requirements-optional.lock exist they are used with --require-hashes.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_VERSION = "3.12"  # the bundled interpreters are python-build-standalone 3.12
# name -> (pip --platform tag, target folder). pip also accepts older macOS versions of each tag,
# so macOS wheels built for 10.x/11.0 are picked up; NodeWatch for Mac needs macOS 11 or later.
TARGETS = {
    "windows": ("win_amd64", ROOT / "runtime" / "site-packages"),
    "macos-arm64": ("macosx_11_0_arm64", ROOT / "runtime-macos" / "site-packages-arm64"),
    "macos-x86_64": ("macosx_11_0_x86_64", ROOT / "runtime-macos" / "site-packages-x86_64"),
}
TARGET = TARGETS["windows"][1]  # default, kept for callers of the v0.10.22 single-platform layout
MARKER_NAME = "NODEWATCH-BUNDLE.json"
# Must match the launcher's self-test (release/native_launcher.go runtimeSelfTest).
REQUIRED = {"fastapi": "0.142.2", "starlette": "1.7.0", "uvicorn": "0.54.0", "jinja2": "3.1.6"}


def _pip_command() -> list[str]:
    """pip of this interpreter, or of a throw-away venv (the bundled interpreter ships no pip)."""
    if subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True).returncode == 0:
        return [sys.executable, "-m", "pip"]
    env_dir = Path(tempfile.mkdtemp(prefix="nodewatch-pip-"))
    venv.EnvBuilder(with_pip=True).create(env_dir)
    py = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    return [str(py), "-m", "pip"]


def _requirement_files() -> list[tuple[Path, bool]]:
    out = []
    for txt, lock in (
        ("requirements.txt", "requirements.lock"),
        ("requirements-optional.txt", "requirements-optional.lock"),
    ):
        if (ROOT / lock).is_file():
            out.append((ROOT / lock, True))
        elif (ROOT / txt).is_file():
            out.append((ROOT / txt, False))
    return out


def _installed(target: Path) -> dict[str, str]:
    found = {}
    for dist in target.glob("*.dist-info"):
        meta = dist / "METADATA"
        name = version = ""
        for line in meta.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
            if name and version:
                break
        if name:
            found[name.lower().replace("_", "-")] = version
    return found


def build(name: str, wheels: str | None, pip: list[str]) -> None:
    platform, target = TARGETS[name]
    skipped: list[str] = []
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for req, hashed in _requirement_files():
        cmd = pip + [
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "--no-compile",  # bytecode goes to the data folder at run time (PYTHONPYCACHEPREFIX)
            "--only-binary=:all:",
            "--platform",
            platform,
            "--python-version",
            PYTHON_VERSION,
            "--implementation",
            "cp",
            "--target",
            str(target),
            "--upgrade",
            "-r",
            str(req),
        ]
        if hashed and name == "windows":  # the lock files pin Windows wheel hashes
            cmd.append("--require-hashes")
        if wheels:
            cmd += ["--no-index", "--find-links", wheels]
        print("+", " ".join(cmd), flush=True)
        optional = req.name.startswith("requirements-optional")
        if subprocess.run(cmd).returncode == 0:
            continue
        if not optional or name == "windows":  # Windows keeps hash-pinned, all-or-nothing installs
            sys.exit(f"{name}: installing {req.name} failed (see above)")
        # Optional parts (SNMP) never block a build: install what exists for this platform, one by
        # one, and report the rest. NodeWatch then shows "SNMP support component missing" there.
        # (Example: cryptography 50.0.1 has no Intel-Mac wheel.)
        req_index = cmd.index("-r")
        base = cmd[:req_index] + [a for a in cmd[req_index + 2 :] if a != "--require-hashes"]
        for line in req.read_text(encoding="utf-8").splitlines():
            spec = line.split("#", 1)[0].strip().rstrip("\\").strip()
            if not spec or spec.startswith("-") or "--hash" in line:
                continue
            if subprocess.run(base + [spec]).returncode != 0:
                skipped.append(spec)
                print(f"NOTE: {name}: optional {spec} is not available for this platform; skipped.", flush=True)

    # Console-script launchers and caches are not needed (NodeWatch runs `python -m app.launcher`).
    for extra in ("bin", "Scripts"):
        shutil.rmtree(target / extra, ignore_errors=True)
    for cache in list(target.rglob("__pycache__")):
        shutil.rmtree(cache, ignore_errors=True)
    for stray in list(target.rglob("*.pyc")):
        stray.unlink()

    packages = _installed(target)
    missing = {k: v for k, v in REQUIRED.items() if packages.get(k) != v}
    if missing:
        sys.exit(f"{name}: bundled versions do not match the launcher's self-test: {missing} (found {packages})")
    (target / MARKER_NAME).write_text(
        json.dumps(
            {
                "platform": platform,
                "python": PYTHON_VERSION,
                "packages": dict(sorted(packages.items())),
                "skipped_optional": skipped,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    files = sum(1 for p in target.rglob("*") if p.is_file())
    size = sum(p.stat().st_size for p in target.rglob("*") if p.is_file())
    print(f"{target.relative_to(ROOT)}: {len(packages)} packages, {files} files, {size / 1e6:.1f} MB")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheels", help="install from this folder of wheels instead of the internet (--no-index)")
    parser.add_argument(
        "--platforms",
        default="windows",
        help="comma-separated: windows, macos-arm64, macos-x86_64, or 'all' (default: windows)",
    )
    args = parser.parse_args()
    names = list(TARGETS) if args.platforms == "all" else [n.strip() for n in args.platforms.split(",") if n.strip()]
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        sys.exit(f"unknown platform(s): {unknown}; choose from {list(TARGETS)} or all")
    pip = _pip_command()
    for name in names:
        build(name, args.wheels, pip)
    print("Next: python release/generate_integrity.py --update-launcher, then build and sign NodeWatch.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
