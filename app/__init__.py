"""NodeWatch application package.

Phase 3 anti-lift guard: when NodeWatch ships, this whole package is one compiled extension module
(``app.cpython-312-darwin.so`` / ``app.cp312-win_amd64.pyd``) that sits next to the install's ``integrity.json``.
If someone lifts that single compiled file into another program, it is no longer beside a NodeWatch
``integrity.json`` that lists it, and importing it refuses.

The guard is deliberately fail-open: it refuses only when it can prove the module has been lifted (it is a
compiled module and there is no integrity.json beside it that lists it by its real hash). On the source tree,
in the test suite, or on any uncertainty, it does nothing — so it can never stop a genuine NodeWatch start.
The launcher's own full-manifest verification remains the primary integrity check; this only raises the bar
against copying the compiled module out on its own, as the hardening brief asks.
"""

from __future__ import annotations


def _verify_not_lifted(module_file: str) -> str | None:
    """Return a refusal reason when the compiled module has clearly been lifted out of its install, else None.

    ``module_file`` is this package's ``__file__``. Any error or ambiguity returns None (allow startup).
    """
    import hashlib
    import json
    import os
    from pathlib import Path

    try:
        if os.environ.get("NODEWATCH_ALLOW_LIFT") == "1":
            return None  # explicit escape hatch for debugging the compiled module in isolation
        path = Path(module_file)
        # Only the compiled, shipped module is guarded. A source checkout (app/__init__.py) is never "lifted".
        if path.suffix.lower() not in {".pyd", ".so"}:
            return None
        manifest_path = path.with_name("integrity.json")
        if not manifest_path.exists():
            return (
                "This NodeWatch component was moved out of its installation and will not run on its own. "
                "Reinstall NodeWatch and run it from its installer."
            )
        listed = json.loads(manifest_path.read_text("utf-8")).get("files", {})
        want = listed.get(path.name)
        if not want:
            return None  # the manifest does not list the module by this name: cannot prove a lift, so allow
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got != want:
            # The module does not match the integrity manifest beside it. The launcher would already refuse a
            # tampered install; allow here so this guard never second-guesses a legitimate start.
            return None
        return None
    except Exception:  # noqa: BLE001 - never let the guard itself stop a genuine start
        return None


_reason = _verify_not_lifted(__file__)
if _reason:
    raise ImportError(_reason)
