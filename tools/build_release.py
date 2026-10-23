"""Build releases from the repository plus the shipped v0.10.42 programs that have no source here.

The version comes from one place, ``app/core/version.py`` (APP_VERSION); every release gets a build id
``<date>-v<version>-pilot-<commit>``. Both are written everywhere a NodeWatch part checks or shows them:

1. ``_internal/app/`` (and the shipped ``docs/`` files) take the repository's content; files listed in
   tests/baselines/removed_files.json are dropped, new app files are added. The build id replaces the repo's
   placeholder APP_BUILD in every app file that carries it (version.py and static/core.js at least).
2. ``integrity.json`` is regenerated with the v0.10.42 rules (every file listed except README.md, integrity.json
   and docs/).
3. Windows launcher: compiled from ``release/windows-launcher`` with the version, build id and the new manifest
   hash written into its constants (Go 1.24.7, the same flags as v0.10.42). A ``*.syso`` resource file in that
   folder (icon and version details, made by the workflow) is linked in.
4. Installer and macOS launcher (shipped v0.10.42 programs): their version text and, for the launcher, the build id
   and manifest hash are replaced in place, so the version must stay 7 characters (0.10.xx).

Windows: the payload zip is rebuilt with unchanged entries copied as they were, and padded to its original size
so it drops into the installer at the same offset.
macOS: works on an unpacked .app folder; the workflow re-signs (ad hoc) and zips it with macOS tools.

    python tools/build_release.py windows --installer <shipped.exe> --out <new.exe> --build <id>
    python tools/build_release.py macos --app <NodeWatch.app folder> --build <id>
    python tools/build_release.py build-id            # prints a build id for this commit
    python tools/build_release.py version             # prints APP_VERSION

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SHIPPED_BUILD = "2026-10-20-v0.10.42-wall-keeps-place"
SHIPPED_VERSION = "0.10.42"


# --------------------------------------------------------------------------- shared rules
def repo_version() -> tuple[str, str]:
    """(APP_VERSION, APP_BUILD placeholder) from app/core/version.py, the one place the version is set."""
    text = (REPO / "app" / "core" / "version.py").read_text("utf-8")
    version = re.search(r'^APP_VERSION = "([^"]+)"', text, re.M).group(1)
    build = re.search(r'^APP_BUILD = "([^"]+)"', text, re.M).group(1)
    if not re.fullmatch(r"0\.10\.\d\d", version):
        raise SystemExit(f"APP_VERSION {version!r}: the shipped installer and macOS launcher take a 7-character version (0.10.xx)")
    return version, build


def build_id() -> str:
    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    bid = f"{day}-v{repo_version()[0]}-pilot-{sha.strip()[:10]}"
    assert len(bid) == len(SHIPPED_BUILD), (bid, len(bid))
    return bid


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def listed(rel: str) -> bool:
    """v0.10.42 rule, checked against both shipped manifests: everything except these is hash-listed."""
    return rel not in ("README.md", "integrity.json") and not rel.startswith("docs/")


def repo_app_files() -> dict[str, bytes]:
    out = {}
    for p in sorted((REPO / "app").rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
            out[p.relative_to(REPO).as_posix()] = p.read_bytes()
    return out


# Files only one platform uses (v0.10.47, report: Windows files in the macOS app). app_window.py is imported
# only on Windows (app/launcher.py); startup.bmp is the Windows launcher's splash.
WINDOWS_ONLY = ("app/core/app_window.py", "branding/startup.bmp")


# Phase 2 (Tier 1): the app package ships as one compiled module (tools/compile_packages.py) instead of source.
# app/launcher.py stays source: the launchers start the backend with "python -m app.launcher", which needs it.
KEEP_SOURCE = ("app/launcher.py",)


def load_compiled(folder: Path | None, build: str) -> dict[str, bytes] | None:
    """{file name: bytes} of the compiled app package, checked to be built from this build id's source."""
    if folder is None:
        return None
    stamp = (folder / "BUILD.txt").read_text("utf-8").strip()
    if stamp != build:
        raise SystemExit(f"compiled packages are for build {stamp!r}, not {build!r}")
    files = {p.name: p.read_bytes() for p in folder.iterdir() if p.suffix in {".pyd", ".so"}}
    if [n.split(".")[0] for n in files] != ["app"]:
        raise SystemExit(f"expected one compiled module named app, found {sorted(files)}")
    return files


def new_internal_files(current: dict[str, bytes], build: str, platform: str,
                       compiled: dict[str, bytes] | None = None) -> tuple[dict[str, bytes], list[str]]:
    """current: rel path under _internal -> bytes (shipped). Returns the new map and a change report."""
    if len(build) != len(SHIPPED_BUILD):
        raise SystemExit(f"build id must be {len(SHIPPED_BUILD)} characters: {build!r}")
    removed = set(json.loads((REPO / "tests" / "baselines" / "removed_files.json").read_text("utf-8")))
    repo = repo_app_files()
    new = dict(current)
    report = []
    for rel in sorted(current):
        if rel.startswith("app/") and not rel.startswith("app/bin/") and rel not in repo:
            if rel not in removed:
                raise SystemExit(f"{rel} is in the shipped build but not in the repo, and not in removed_files.json")
            del new[rel]
            report.append(f"removed  {rel}")
    for rel, data in repo.items():
        if rel.startswith("app/bin/"):
            continue
        if rel not in current:
            report.append(f"added    {rel}")
        elif current[rel] != data:
            report.append(f"changed  {rel}")
        new[rel] = data
    # v0.10.44: no documentation in the installed app (internal notes stay in the repository).
    # v0.10.48: branding/README.txt is an internal note (it explained how to swap the splash image).
    dropped = [rel for rel in new if rel.startswith("docs/") or rel in {"README.md", "branding/README.txt"}]
    for rel in dropped:
        del new[rel]
    if dropped:
        report.append(f"removed  docs/, README.md and branding/README.txt ({len(dropped)} files)")
    if platform == "macos":
        for rel in WINDOWS_ONLY:
            if new.pop(rel, None) is not None:
                report.append(f"removed  {rel} (Windows only)")
    if compiled is not None:
        # The packages' source is replaced by their compiled modules (stamped with the build id before compiling).
        gone = [rel for rel in new if rel.startswith("app/") and rel.endswith(".py") and rel not in KEEP_SOURCE]
        for rel in gone:
            del new[rel]
        for name, data in compiled.items():
            new[name] = data  # beside the app folder: _internal/app.<suffix>
        report.append(f"compiled: {len(gone)} app source files replaced by {sorted(compiled)} (kept: {', '.join(KEEP_SOURCE)})")
    version, placeholder = repo_version()
    if f"const FRONTEND_VERSION = '{version}';" not in new["app/static/core.js"].decode("utf-8"):
        raise SystemExit(f"app/static/core.js FRONTEND_VERSION is not {version} (set both with the version)")
    # The build id is written in the backend (version.py) and the page (static/core.js FRONTEND_BUILD, compared
    # with the backend's on every status read). Replace it in every app file that carries it, and require both.
    stamped = []
    for rel in sorted(new):
        if rel.startswith("app/") and not rel.startswith("app/bin/") and placeholder.encode() in new[rel]:
            new[rel] = new[rel].replace(placeholder.encode(), build.encode())
            stamped.append(rel)
    required = {"app/static/core.js"} if compiled is not None else {"app/core/version.py", "app/static/core.js"}
    if not required <= set(stamped):
        raise SystemExit(f"build id not found where expected; stamped: {stamped}")
    report.append(f"build id {build} written to: {', '.join(stamped)}")
    old_manifest = json.loads(current["integrity.json"])
    order = [r for r in old_manifest["files"] if r in new] + sorted(r for r in new if listed(r) and r not in old_manifest["files"])
    manifest = {"build": build, "files": {r: sha256(new[r]) for r in order if listed(r)}}
    missing = [r for r in new if listed(r) and r not in manifest["files"]]
    assert not missing, missing
    new["integrity.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    report.append(f"integrity.json: {len(manifest['files'])} files listed (was {len(old_manifest['files'])})")
    return new, report


def patch_launcher(binary: bytes, old_manifest_sha: str, new_manifest_sha: str, build: str, copies: int) -> bytes:
    """Shipped macOS launcher: manifest hash, build id and version text (one copy per architecture)."""
    version = repo_version()[0]
    for old, new in ((old_manifest_sha, new_manifest_sha), (SHIPPED_BUILD, build), (SHIPPED_VERSION, version)):
        found = binary.count(old.encode())
        if found != copies:
            raise SystemExit(f"launcher holds {found} copies of {old!r}, expected {copies}")
        binary = binary.replace(old.encode(), new.encode())
    return binary


def compile_windows_launcher(manifest_sha: str, build: str) -> bytes:
    """release/windows-launcher with this release's constants, built exactly like v0.10.42 (Go 1.24.7)."""
    version = repo_version()[0]
    go_version = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True, check=True).stdout.strip()
    if go_version != "go1.24.7":
        raise SystemExit(f"the Windows launcher is built with go1.24.7 (as v0.10.42), not {go_version}")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "launcher"
        shutil.copytree(REPO / "release" / "windows-launcher", src)
        main = src / "main.go"
        text = main.read_text("utf-8")
        for name, value in (("appVersion", version), ("appBuild", build), ("manifestSHA256", manifest_sha)):
            text, n = re.subn(rf'^(\t{name}\s*=\s*")[^"]*(")', rf"\g<1>{value}\g<2>", text, flags=re.M)
            if n != 1:
                raise SystemExit(f"constant {name} not found exactly once in release/windows-launcher/main.go")
        main.write_text(text, "utf-8")
        out = Path(tmp) / "NodeWatch.exe"
        env = dict(os.environ, GOOS="windows", GOARCH="amd64", CGO_ENABLED="0")
        subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w -H windowsgui", "-o", str(out), "."],
                       cwd=src, env=env, check=True)
        data = out.read_bytes()
    for needle in (version, build, manifest_sha):
        if needle.encode() not in data:
            raise SystemExit(f"built launcher does not contain {needle!r}")
    return data


def stamp_installer(exe: bytes, start: int, size: int) -> tuple[bytes, int]:
    """Version text of the shipped installer (outside its payload), ASCII and UTF-16. Same length, so in place."""
    version = repo_version()[0]
    head, payload, tail = exe[:start], exe[start:start + size], exe[start + size:]
    count = 0
    for old, new in ((SHIPPED_VERSION.encode(), version.encode()),
                     (SHIPPED_VERSION.encode("utf-16-le"), version.encode("utf-16-le"))):
        count += head.count(old) + tail.count(old)
        head, tail = head.replace(old, new), tail.replace(old, new)
    return head + payload + tail, count


# --------------------------------------------------------------------------- Windows
EOCD, CDH, LFH = b"PK\x05\x06", b"PK\x01\x02", b"PK\x03\x04"


def read_payload(exe: bytes):
    end = exe.rfind(EOCD)
    n_entries = struct.unpack_from("<H", exe, end + 10)[0]
    cd_size, cd_off, clen = struct.unpack_from("<IIH", exe, end + 12)
    start = end - cd_size - cd_off
    zipb = exe[start:end + 22 + clen]
    entries, p = [], cd_off
    for _ in range(n_entries):
        assert zipb[p:p + 4] == CDH
        (vm, vn, flag, meth, mtime, mdate, crc, csize, usize, nlen, xlen, clen2, disk, iattr, eattr,
         lho) = struct.unpack_from("<HHHHHHIIIHHHHHII", zipb, p + 4)
        name = zipb[p + 46:p + 46 + nlen].decode("utf-8" if flag & 0x800 else "cp437")
        extra = zipb[p + 46 + nlen:p + 46 + nlen + xlen]
        comment = zipb[p + 46 + nlen + xlen:p + 46 + nlen + xlen + clen2]
        assert zipb[lho:lho + 4] == LFH
        lnlen, lxlen = struct.unpack_from("<HH", zipb, lho + 26)
        data_at = lho + 30 + lnlen + lxlen
        entries.append(dict(vm=vm, vn=vn, flag=flag, meth=meth, mtime=mtime, mdate=mdate, crc=crc, csize=csize,
                            usize=usize, name=name, extra=extra, comment=comment, iattr=iattr, eattr=eattr,
                            local=zipb[lho:data_at], raw=zipb[data_at:data_at + csize]))
        p += 46 + nlen + xlen + clen2
    return start, len(zipb), zipb, entries


def inflate(e) -> bytes:
    if e["meth"] == 0:
        return e["raw"]
    if e["meth"] == 8:
        return zlib.decompress(e["raw"], -15)
    raise SystemExit(f"unsupported compression {e['meth']} for {e['name']}")


def write_payload(entries, target_size: int) -> bytes:
    body, cds = bytearray(), bytearray()
    for e in entries:
        off = len(body)
        if e.get("data") is None:  # unchanged: copy the local header and compressed bytes as shipped
            local, raw, crc, csize, usize, meth = e["local"], e["raw"], e["crc"], e["csize"], e["usize"], e["meth"]
            if e["flag"] & 0x8:
                raise SystemExit(f"{e['name']}: data descriptors are not supported")
        else:
            data = e["data"]
            crc, usize = zlib.crc32(data) & 0xFFFFFFFF, len(data)
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            raw = co.compress(data) + co.flush()
            meth = 8
            if len(raw) >= usize:
                raw, meth = data, 0
            csize = len(raw)
            name = e["name"].encode("utf-8")
            flag = e["flag"] & ~0x8
            local = LFH + struct.pack("<HHHHHIIIHH", e["vn"], flag, meth, e["mtime"], e["mdate"], crc, csize, usize,
                                       len(name), 0) + name
        body += local + raw
        name = e["name"].encode("utf-8")
        flag = e["flag"] & ~0x8 if e.get("data") is not None else e["flag"]
        cds += CDH + struct.pack("<HHHHHHIIIHHHHHII", e["vm"], e["vn"], flag, meth, e["mtime"], e["mdate"], crc, csize,
                                 usize, len(name), len(e["extra"]), len(e["comment"]), 0, e["iattr"], e["eattr"], off)
        cds += name + e["extra"] + e["comment"]
    pad = target_size - (len(body) + len(cds) + 22)
    if pad < 0:
        raise SystemExit(f"new payload is {-pad} bytes larger than the shipped one; it cannot replace it in place")
    # Padding sits between the last file and the central directory: zip readers follow the directory's offsets.
    body += b"\0" * pad
    eocd = EOCD + struct.pack("<HHHHIIH", 0, 0, len(entries), len(entries), len(cds), len(body), 0)
    return bytes(body + cds + eocd)


def build_windows_tree(installer: Path, out_dir: Path, build: str, compiled: dict[str, bytes] | None) -> None:
    """The installed folder (NodeWatch/NodeWatch.exe and NodeWatch/_internal) written out, without an installer:
    used while a compiled payload no longer fits the shipped installer's fixed payload slot."""
    exe = installer.read_bytes()
    _, _, _, entries = read_payload(exe)
    prefix = "NodeWatch/_internal/"
    current = {e["name"][len(prefix):]: inflate(e) for e in entries if e["name"].startswith(prefix) and not e["name"].endswith("/")}
    new, report = new_internal_files(current, build, "windows", compiled)
    launcher = compile_windows_launcher(sha256(new["integrity.json"]), build)
    root = out_dir / "NodeWatch"
    for rel, data in new.items():
        path = root / "_internal" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / "NodeWatch.exe").write_bytes(launcher)
    print("\n".join(report))
    print(f"tree written to {root} ({len(new)} files), manifest {sha256(new['integrity.json'])}, build {build}")


def build_windows(installer: Path, out: Path, build: str, compiled: dict[str, bytes] | None = None) -> None:
    exe = installer.read_bytes()
    start, size, _, entries = read_payload(exe)
    prefix = "NodeWatch/_internal/"
    current = {e["name"][len(prefix):]: inflate(e) for e in entries if e["name"].startswith(prefix) and not e["name"].endswith("/")}
    launcher_entry = next(e for e in entries if e["name"] == "NodeWatch/NodeWatch.exe")
    new, report = new_internal_files(current, build, "windows", compiled)
    launcher = compile_windows_launcher(sha256(new["integrity.json"]), build)

    kept = []
    for e in entries:
        rel = e["name"][len(prefix):] if e["name"].startswith(prefix) else None
        if e is launcher_entry:
            kept.append({**e, "data": launcher})
        elif rel is None or e["name"].endswith("/"):
            if rel is None or not (rel.startswith("docs/") or rel == "docs/"):
                kept.append(e)
        elif rel in new:
            kept.append(e if new[rel] == current[rel] else {**e, "data": new[rel]})
        # else: removed
    template = next(e for e in entries if e["name"].startswith(prefix + "app/core/") and not e["name"].endswith("/"))
    for rel in sorted(set(new) - set(current)):
        kept.append({**template, "name": prefix + rel, "extra": b"", "comment": b"", "data": new[rel]})
    payload = write_payload(kept, size)
    result = exe[:start] + payload + exe[start + size:]
    result, stamped = stamp_installer(result, start, size)
    if stamped < 4:
        raise SystemExit(f"installer version text found {stamped} times, expected at least 4")
    assert len(result) == len(exe)
    out.write_bytes(result)
    print("\n".join(report))
    print(f"launcher built from source: version {repo_version()[0]}, manifest {sha256(new['integrity.json'])}, build {build}")
    print(f"installer version text replaced in {stamped} places")
    print(f"installer: {out} ({len(result)} bytes, sha256 {sha256(result)})")


# --------------------------------------------------------------------------- macOS
def build_macos(app: Path, build: str, compiled: dict[str, bytes] | None = None) -> None:
    internal = app / "Contents" / "Resources" / "_internal"
    current = {p.relative_to(internal).as_posix(): p.read_bytes() for p in internal.rglob("*") if p.is_file()}
    new, report = new_internal_files(current, build, "macos", compiled)
    for rel in set(current) - set(new):
        (internal / rel).unlink()
    if compiled is not None:
        for d in sorted((internal / "app").rglob("*"), key=lambda x: len(x.parts), reverse=True):
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()
    shutil.rmtree(internal / "docs", ignore_errors=True)
    for rel, data in new.items():
        if current.get(rel) != data:
            path = internal / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    launcher_path = app / "Contents" / "MacOS" / "NodeWatch"
    launcher_path.write_bytes(patch_launcher(launcher_path.read_bytes(), sha256(current["integrity.json"]),
                                             sha256(new["integrity.json"]), build, 2))  # universal: arm64 + x86_64
    plist = app / "Contents" / "Info.plist"
    text = plist.read_text("utf-8")
    if text.count(f"<string>{SHIPPED_VERSION}</string>") != 2:
        raise SystemExit("Info.plist does not hold the v0.10.42 version twice")
    plist.write_text(text.replace(f"<string>{SHIPPED_VERSION}</string>", f"<string>{repo_version()[0]}</string>"), "utf-8")
    print("\n".join(report))
    print(f"launcher patched: manifest {sha256(new['integrity.json'])}, build {build}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("windows")
    w.add_argument("--installer", type=Path, required=True)
    w.add_argument("--out", type=Path, required=True)
    w.add_argument("--build", required=True)
    w.add_argument("--compiled", type=Path, help="folder from tools/compile_packages.py (Phase 2)")
    t = sub.add_parser("windows-tree")
    t.add_argument("--installer", type=Path, required=True)
    t.add_argument("--out-dir", type=Path, required=True)
    t.add_argument("--build", required=True)
    t.add_argument("--compiled", type=Path)
    m = sub.add_parser("macos")
    m.add_argument("--app", type=Path, required=True)
    m.add_argument("--build", required=True)
    m.add_argument("--compiled", type=Path)
    sub.add_parser("build-id")
    sub.add_parser("version")
    args = ap.parse_args()
    if args.cmd == "build-id":
        print(build_id())
    elif args.cmd == "version":
        print(repo_version()[0])
    elif args.cmd == "windows":
        build_windows(args.installer, args.out, args.build, load_compiled(args.compiled, args.build))
    elif args.cmd == "windows-tree":
        build_windows_tree(args.installer, args.out_dir, args.build, load_compiled(args.compiled, args.build))
    else:
        build_macos(args.app, args.build, load_compiled(args.compiled, args.build))
    return 0


if __name__ == "__main__":
    sys.exit(main())
