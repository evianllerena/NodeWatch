"""Phase 2 (Tier 1): compile the app package into one native module with Nuitka (free edition).

``app.cp312-win_amd64.pyd`` / ``app.cpython-312-darwin.so`` holds every module of app/ (core, integrations,
services, and the thin routers in modules/ and main.py) and replaces their source in the build
(tools/build_release.py --compiled). app/launcher.py stays source because the backend is started with
"python -m app.launcher"; templates, static files and app/bin stay files. The build id is written into a copy of
the source first, exactly as the release tool does, because version.py is compiled in. No docstrings.

    python tools/compile_packages.py --build <build id> --out <folder>

Needs Python 3.12 (the version the app ships with), Nuitka and a C compiler (MSVC on Windows, clang on macOS).
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from build_release import repo_version  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--jobs", type=int, default=0)
    args = ap.parse_args()
    if sys.version_info[:2] != (3, 12):
        raise SystemExit(f"compile with Python 3.12 (the shipped runtime); this is {sys.version.split()[0]}")
    _, placeholder = repo_version()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nw-compile-") as tmp:
        work = Path(tmp)
        shutil.copytree(REPO / "app", work / "app", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        stamped = []
        for path in (work / "app").rglob("*.py"):
            text = path.read_bytes()
            if placeholder.encode() in text:
                path.write_bytes(text.replace(placeholder.encode(), args.build.encode()))
                stamped.append(path.relative_to(work).as_posix())
        if "app/core/version.py" not in stamped:
            raise SystemExit("build id placeholder not found in app/core/version.py")
        print(f"build id {args.build} written to {stamped}")
        suffix = sysconfig.get_config_var("EXT_SUFFIX")
        cmd = [
            sys.executable, "-m", "nuitka", "--mode=module", "app", "--include-package=app",
            "--nofollow-import-to=app.launcher", f"--output-dir={out}", "--remove-output", "--no-pyi-file",
            "--python-flag=no_docstrings", "--assume-yes-for-downloads", f"--report={out / 'compile-report.xml'}",
        ]
        if args.jobs:
            cmd.append(f"--jobs={args.jobs}")
        print("+", " ".join(cmd), flush=True)
        subprocess.run(cmd, cwd=work, check=True)
        built = out / f"app{suffix}"
        if not built.is_file():
            raise SystemExit(f"{built.name} was not produced; output folder has {sorted(p.name for p in out.iterdir())}")
        print(f"{built.name}: {built.stat().st_size} bytes", flush=True)
        # Every app module must be inside (Nuitka only includes what it is told to).
        report = (out / "compile-report.xml").read_text("utf-8", "replace")
        expected = sorted(
            ".".join(p.relative_to(work).with_suffix("").parts).removesuffix(".__init__")
            for p in (work / "app").rglob("*.py") if p.name != "launcher.py" or p.parent.name != "app"
        )
        named = set(re.findall(r"""\bname=["']([\w.]+)["']""", report))
        missing = [m for m in expected if m not in named]
        if missing:
            raise SystemExit(f"{len(missing)} app modules are not in the compiled module, for example {missing[:10]}")
        print(f"all {len(expected)} app modules compiled in", flush=True)
    (out / "BUILD.txt").write_text(args.build + "\n", "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
