"""Phase 3 protection verification: check an installed NodeWatch and write a one-page report.

Run against an installed _internal folder (Windows: ...\\NodeWatch\\_internal; macOS: NodeWatch.app/Contents/
Resources/_internal) with the repository checked out alongside, so the compiled module can be compared with its
own source:

    python tools/protection_check.py --internal <_internal folder> --report protection.md

Checks (each a hard gate):
  1. No Python source ships except app/launcher.py (no .py/.pyc for the compiled app).
  2. The app is one compiled extension module (app.<suffix>), not source.
  3. Comments and docstrings from the source are not found in the compiled module (readable source is gone).
  4. integrity.json is present, and the launcher binary pins its SHA-256.
  5. No debug files (.pdb, .map, __pycache__) and no docs ship.

The live anti-tamper check (changing a listed file makes the launcher refuse to start) is done by the workflow,
which can run the launcher; this tool records its result when given --tamper-result.
Standard library only.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import sys
import time
import tokenize
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMPILED_PACKAGES = ("core", "integrations", "services", "modules", "ui")  # everything under app/ except launcher.py


def _source_comments_and_docstrings(limit: int = 60) -> list[str]:
    """Distinctive comment lines and docstrings from the repo's app/ source (things that must not ship)."""
    out: list[str] = []
    for py in sorted((REPO / "app").rglob("*.py")):
        if py.name == "launcher.py":
            continue
        text = py.read_text("utf-8", "replace")
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    body = tok.string.lstrip("#").strip()
                    if len(body) >= 45 and sum(c.isalpha() for c in body) >= 30 and "noqa" not in body:
                        out.append(body)
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            doc = ast.get_docstring(node) if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) else None
            if doc:
                line = doc.strip().splitlines()[0].strip()
                if len(line) >= 45 and sum(c.isalpha() for c in line) >= 30:
                    out.append(line)
    # A spread-out sample, de-duplicated, so the check is fast but covers many files.
    seen = list(dict.fromkeys(out))
    step = max(1, len(seen) // limit)
    return seen[::step][:limit]


def check(internal: Path, tamper_result: str | None) -> tuple[list[tuple[str, bool, str]], str]:
    results: list[tuple[str, bool, str]] = []

    def gate(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))

    app = internal / "app"
    stray = [p.relative_to(internal).as_posix() for p in app.rglob("*") if p.suffix in {".py", ".pyc"}] if app.exists() else []
    gate("Only app/launcher.py ships as Python source", stray == ["app/launcher.py"], f"found: {stray}")

    modules = sorted(p.name for p in internal.glob("app.*") if p.suffix in {".pyd", ".so"})
    gate("The app is one compiled module", len(modules) == 1, f"modules: {modules}")

    markers = _source_comments_and_docstrings()
    leaked: list[str] = []
    if modules:
        blob = (internal / modules[0]).read_bytes()
        for m in markers:
            if m.encode("utf-8") in blob:
                leaked.append(m)
    gate("No source comments or docstrings in the compiled module",
         bool(markers) and not leaked, f"checked {len(markers)} markers; leaked {len(leaked)}: {leaked[:3]}")

    manifest_path = internal / "integrity.json"
    manifest_ok = manifest_path.exists()
    manifest = json.loads(manifest_path.read_text("utf-8")) if manifest_ok else {"files": {}}
    gate("integrity.json present", manifest_ok, f"{len(manifest.get('files', {}))} files listed")

    # The launcher (Windows: ..\\NodeWatch.exe; macOS: ..\\..\\MacOS\\NodeWatch) pins the manifest's SHA-256.
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_ok else ""
    launcher = internal.parent / "NodeWatch.exe"
    if not launcher.exists():
        launcher = internal.parent.parent / "MacOS" / "NodeWatch"
    pinned = launcher.exists() and manifest_sha.encode() in launcher.read_bytes()
    gate("The launcher pins the integrity manifest hash", pinned, f"{launcher.name}: {manifest_sha[:12]}")

    debris = [p.relative_to(internal).as_posix() for p in internal.rglob("*")
              if p.suffix in {".pdb", ".map"} or p.name == "__pycache__" or p.name == "README.md"
              or p.as_posix().startswith((str(internal / "docs")))]
    gate("No debug files, __pycache__ or docs ship", not debris, f"found: {debris[:5]}")

    if tamper_result is not None:
        gate("Changing a listed file makes the launcher refuse to start", tamper_result == "refused",
             f"launcher result: {tamper_result}")

    lines = [
        f"# NodeWatch protection verification — {manifest.get('build', '?')}",
        "",
        f"Generated {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())} by tools/protection_check.py.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for name, ok, detail in results:
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
    lines += ["", "Anti-lift: the compiled module refuses to run when copied out of its install (app/__init__.py).",
              "Decompile resistance is evidenced by the workflow (native extension; bytecode decompilers reject it).",
              "Left to the pentest: an adversarial decompile-and-LLM read of a compiled module by a human expert."]
    return results, "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--internal", type=Path, required=True)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--tamper-result", choices=["refused", "started"], help="result of the workflow's live tamper test")
    args = ap.parse_args()
    results, report = check(args.internal, args.tamper_result)
    if args.report:
        args.report.write_text(report, "utf-8")
    print(report)
    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print(f"\nFAILED: {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
