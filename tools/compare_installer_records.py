"""Compare two installer recordings (tools/installer_parity.ps1): the shipped v0.10.42 installer and a new one.

Versions, dates, sizes, process ids and the runner's own churn are normalised away; what is left must match:
exit codes, the windows and texts the user sees, shortcuts, the Settings › Apps entry, the files NodeWatch
installs (outside _internal, which changes with every release) and what the uninstaller removes.
Prints a report and exits 1 on any difference that is not listed in ALLOWED.

    python tools/compare_installer_records.py <shipped folder> <new folder>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSION = re.compile(r"\b0\.10\.\d{2}\b")

# Differences that are expected, with the reason.
ALLOWED = {
    "5-wizard-pages.txt": "the progress line on the Installing page shows other step names while files are copied",
    "1-silent-files.txt": "_internal sizes change with every release",
    "5-wizard-files.txt": "the started app writes its browser cache; only NodeWatch lines outside it are compared",
}


def norm(name: str, text: str) -> list[str]:
    lines = []
    for line in text.replace("\r", "").split("\n"):
        line = VERSION.sub("<v>", line.rstrip())
        line = re.sub(r"\[InstallDate\] = \d{8}", "[InstallDate] = <date>", line)
        line = re.sub(r"\[EstimatedSize\] = \d+", "[EstimatedSize] = <size>", line)
        line = re.sub(r"\[\d+\] = ", "[n] = ", line)  # UFH\SHC counters
        line = re.sub(r"\|\d+$", "|<size>", line)  # file sizes
        line = re.sub(r"files under _internal: \d+, \d+ bytes", "files under _internal: <n>", line)
        line = re.sub(r"processes now: .*", "processes now: <started>", line)
        if "files" in name or "registry" in name:
            low = line.lower()
            if "nodewatch" not in low or "\\app-window\\" in low or "\\pycache\\" in low or "\\logs\\" in low or "\\state\\" in low:
                if not line.startswith(("ADDED", "REMOVED")):
                    continue
            if line.startswith(("ADDED", "REMOVED")):
                line = re.sub(r"\(\d+\)", "", line)
            if "MuiCache" in line or "\\UFH\\" in line or "App Paths" in line:
                continue  # written by Windows / the app at run time, not by the installer
        if "pages" in name and line.strip().startswith("'") and line.strip().endswith("…'"):
            continue  # progress text
        if line.strip():
            lines.append(line)
    return lines


def main() -> int:
    old_dir, new_dir = Path(sys.argv[1]), Path(sys.argv[2])
    names = sorted({p.name for p in old_dir.glob("*.txt")} | {p.name for p in new_dir.glob("*.txt")})
    failed = False
    for name in names:
        a, b = old_dir / name, new_dir / name
        if not a.exists() or not b.exists():
            print(f"MISSING {name}: shipped={a.exists()} new={b.exists()}")
            failed = True
            continue
        x, y = norm(name, a.read_text("utf-8", "replace")), norm(name, b.read_text("utf-8", "replace"))
        if x == y:
            print(f"same    {name}")
            continue
        only_old = [l for l in x if l not in y]
        only_new = [l for l in y if l not in x]
        if not only_old and not only_new:
            print(f"same    {name} (order differs)")
            continue
        tag = "allowed" if name in ALLOWED else "DIFFERS"
        failed |= name not in ALLOWED
        print(f"{tag} {name}" + (f" ({ALLOWED[name]})" if name in ALLOWED else ""))
        for l in only_old[:25]:
            print(f"    shipped only: {l}")
        for l in only_new[:25]:
            print(f"    new only:     {l}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
