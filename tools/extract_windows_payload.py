"""Extract the files embedded in the Windows installer (NodeWatch.exe, Go build path nodewatch/setup).

The installer carries its payload as a zip archive inside the executable: the inner launcher
NodeWatch/NodeWatch.exe plus NodeWatch/_internal/**. This script finds that archive, extracts it to a
folder, and checks every extracted file against the extracted _internal/integrity.json.

    python tools/extract_windows_payload.py <installer.exe> <output folder>

Standard library only. It never runs anything from the installer.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

EOCD = b"PK\x05\x06"
LOCAL = b"PK\x03\x04"


def payload_zip(data: bytes) -> zipfile.ZipFile:
    end = data.rfind(EOCD)
    if end < 0:
        raise SystemExit("no zip end-of-central-directory record found in the installer")
    comment_len = struct.unpack_from("<H", data, end + 20)[0]
    cd_size, cd_offset = struct.unpack_from("<II", data, end + 12)
    start = end - cd_size - cd_offset  # where offset 0 of the archive sits inside the exe
    if start < 0 or data[start:start + 4] != LOCAL:
        start = data.find(LOCAL)  # fallback: first local file header
    blob = data[start:end + 22 + comment_len]
    zf = zipfile.ZipFile(io.BytesIO(blob))
    bad = zf.testzip()
    if bad:
        raise SystemExit(f"payload zip is corrupt at {bad}")
    return zf


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    exe, out = Path(sys.argv[1]), Path(sys.argv[2])
    zf = payload_zip(exe.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    for info in zf.infolist():
        target = (out / info.filename).resolve()
        if not str(target).startswith(str(out.resolve())):
            raise SystemExit(f"unsafe path in payload: {info.filename}")
    zf.extractall(out)
    internal = out / "NodeWatch" / "_internal"
    manifest = json.loads((internal / "integrity.json").read_text(encoding="utf-8"))
    bad = [rel for rel, digest in manifest["files"].items()
           if not (internal / rel).is_file() or hashlib.sha256((internal / rel).read_bytes()).hexdigest() != digest]
    print(f"entries={len(zf.infolist())} build={manifest.get('build')} listed={len(manifest['files'])} mismatched={len(bad)}")
    if bad:
        print("first mismatches:", bad[:5])
        return 1
    print(f"internal={internal}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
