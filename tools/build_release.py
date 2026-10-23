"""Build pilot releases from the shipped v0.10.42 builds plus the repository's app/ source.

The launchers, installer, runtimes and window binaries stay exactly the shipped v0.10.42 binaries. Only three
things change, and each is checked:

1. ``_internal/app/`` (and the shipped ``docs/`` files) take the repository's content; files listed in
   tests/baselines/removed_files.json are dropped, new app files are added.
2. ``app/core/version.py`` gets a new APP_BUILD of the same length, and ``integrity.json`` is regenerated with the
   v0.10.42 rules (every file listed except README.md, integrity.json and docs/).
3. The launcher binary has its pinned integrity.json hash and its build string replaced, byte for byte
   (same length, each must occur the expected number of times).

Windows: the payload zip is rebuilt with unchanged entries copied as they were, and padded to its original size
so it drops into the installer at the same offset; nothing else in the installer changes.
macOS: works on an unpacked .app folder; the workflow re-signs (ad hoc) and zips it with macOS tools.

    python tools/build_release.py windows --installer <shipped.exe> --out <new.exe> --build <id>
    python tools/build_release.py macos --app <NodeWatch.app folder> --build <id>
    python tools/build_release.py build-id            # prints a build id for this commit

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SHIPPED_BUILD = "2026-10-20-v0.10.42-wall-keeps-place"
SHIPPED_VERSION = "0.10.42"


# --------------------------------------------------------------------------- shared rules
def build_id() -> str:
    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    bid = f"{day}-v{SHIPPED_VERSION}-pilot-{sha.strip()[:10]}"
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


def new_internal_files(current: dict[str, bytes], build: str) -> tuple[dict[str, bytes], list[str]]:
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
    for rel in sorted(current):  # shipped docs take the repo's text when it changed; dev-only docs are not shipped
        if rel.startswith("docs/") and (REPO / rel).is_file() and (REPO / rel).read_bytes() != current[rel]:
            new[rel] = (REPO / rel).read_bytes()
            report.append(f"changed  {rel}")
    version = new["app/core/version.py"].decode("utf-8")
    if f'APP_BUILD = "{SHIPPED_BUILD}"' not in version or f'APP_VERSION = "{SHIPPED_VERSION}"' not in version:
        raise SystemExit("app/core/version.py no longer holds the v0.10.42 version and build")
    new["app/core/version.py"] = version.replace(SHIPPED_BUILD, build).encode("utf-8")
    old_manifest = json.loads(current["integrity.json"])
    order = [r for r in old_manifest["files"] if r in new] + sorted(r for r in new if listed(r) and r not in old_manifest["files"])
    manifest = {"build": build, "files": {r: sha256(new[r]) for r in order if listed(r)}}
    missing = [r for r in new if listed(r) and r not in manifest["files"]]
    assert not missing, missing
    new["integrity.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    report.append(f"integrity.json: {len(manifest['files'])} files listed (was {len(old_manifest['files'])})")
    return new, report


def patch_launcher(binary: bytes, old_manifest_sha: str, new_manifest_sha: str, build: str, copies: int) -> bytes:
    for old, new in ((old_manifest_sha, new_manifest_sha), (SHIPPED_BUILD, build)):
        found = binary.count(old.encode())
        if found != copies:
            raise SystemExit(f"launcher holds {found} copies of {old!r}, expected {copies}")
        binary = binary.replace(old.encode(), new.encode())
    return binary


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


def build_windows(installer: Path, out: Path, build: str) -> None:
    exe = installer.read_bytes()
    start, size, _, entries = read_payload(exe)
    prefix = "NodeWatch/_internal/"
    current = {e["name"][len(prefix):]: inflate(e) for e in entries if e["name"].startswith(prefix) and not e["name"].endswith("/")}
    launcher_entry = next(e for e in entries if e["name"] == "NodeWatch/NodeWatch.exe")
    new, report = new_internal_files(current, build)
    launcher = patch_launcher(inflate(launcher_entry), sha256(current["integrity.json"]), sha256(new["integrity.json"]), build, 1)

    kept = []
    for e in entries:
        rel = e["name"][len(prefix):] if e["name"].startswith(prefix) else None
        if e is launcher_entry:
            kept.append({**e, "data": launcher})
        elif rel is None or e["name"].endswith("/"):
            kept.append(e)
        elif rel in new:
            kept.append(e if new[rel] == current[rel] else {**e, "data": new[rel]})
        # else: removed
    template = next(e for e in entries if e["name"].startswith(prefix + "app/core/") and not e["name"].endswith("/"))
    for rel in sorted(set(new) - set(current)):
        kept.append({**template, "name": prefix + rel, "extra": b"", "comment": b"", "data": new[rel]})
    payload = write_payload(kept, size)
    result = exe[:start] + payload + exe[start + size:]
    assert len(result) == len(exe)
    out.write_bytes(result)
    print("\n".join(report))
    print(f"launcher patched: manifest {sha256(new['integrity.json'])}, build {build}")
    print(f"installer: {out} ({len(result)} bytes, sha256 {sha256(result)})")


# --------------------------------------------------------------------------- macOS
def build_macos(app: Path, build: str) -> None:
    internal = app / "Contents" / "Resources" / "_internal"
    current = {p.relative_to(internal).as_posix(): p.read_bytes() for p in internal.rglob("*") if p.is_file()}
    new, report = new_internal_files(current, build)
    for rel in set(current) - set(new):
        (internal / rel).unlink()
    for rel, data in new.items():
        if current.get(rel) != data:
            path = internal / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    launcher_path = app / "Contents" / "MacOS" / "NodeWatch"
    launcher_path.write_bytes(patch_launcher(launcher_path.read_bytes(), sha256(current["integrity.json"]),
                                             sha256(new["integrity.json"]), build, 2))  # universal: arm64 + x86_64
    print("\n".join(report))
    print(f"launcher patched: manifest {sha256(new['integrity.json'])}, build {build}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("windows")
    w.add_argument("--installer", type=Path, required=True)
    w.add_argument("--out", type=Path, required=True)
    w.add_argument("--build", required=True)
    m = sub.add_parser("macos")
    m.add_argument("--app", type=Path, required=True)
    m.add_argument("--build", required=True)
    sub.add_parser("build-id")
    args = ap.parse_args()
    if args.cmd == "build-id":
        print(build_id())
    elif args.cmd == "windows":
        build_windows(args.installer, args.out, args.build)
    else:
        build_macos(args.app, args.build)
    return 0


if __name__ == "__main__":
    sys.exit(main())
