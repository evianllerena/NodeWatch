"""Upgrade check: open the page of one build, then of the next, in the same browser profile, as a user's app
window does across an upgrade. Fails if the page of the last build is not that build (a stale cached script
shows "Build mismatch").

    python tools/upgrade_check.py <_internal of build 1> <_internal of build 2> [...]

Needs the app's Python packages (tests/requirements-ci.txt) and Playwright with Chromium.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

PORT = 8799


def serve(internal: str, data: str) -> subprocess.Popen:
    env = dict(os.environ, NODEWATCH_DATA=data, PYTHONDONTWRITEBYTECODE="1")
    env["PYTHONPATH"] = os.pathsep.join(p for p in (internal, env.get("PYTHONPATH", "")) if p)
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
                            cwd=internal, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/status?probe=true", timeout=1) as r:
                return proc, json.loads(r.read())["build"]
        except Exception:
            time.sleep(0.5)
    proc.kill()
    raise SystemExit(f"backend from {internal} did not start")


async def page_build(profile: str) -> tuple[str, str]:
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(profile)
        page = await ctx.new_page()
        await page.goto(f"http://127.0.0.1:{PORT}/", wait_until="load")
        await page.wait_for_timeout(2500)
        build = await page.evaluate("typeof FRONTEND_BUILD !== 'undefined' ? FRONTEND_BUILD : ''")
        pill = (await page.text_content("#connectionPill") or "").strip()
        await ctx.close()
        return build, pill


def main() -> int:
    trees = sys.argv[1:]
    if len(trees) < 2:
        print(__doc__)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        profile, data = os.path.join(tmp, "profile"), os.path.join(tmp, "data")
        ok = True
        for i, tree in enumerate(trees):
            proc, backend = serve(tree, data)
            try:
                page, pill = asyncio.run(page_build(profile))
            finally:
                proc.terminate()
                proc.wait()
            same = page == backend and "Build mismatch" not in pill
            print(f"{'ok ' if same else 'BAD'} step {i + 1}: backend {backend}, page {page}, status '{pill[:90]}'")
            ok = same if i == len(trees) - 1 else ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
